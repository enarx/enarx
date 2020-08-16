// SPDX-License-Identifier: Apache-2.0

//! A typestate builder to enforce the virtual machine is constructed in the right
//! order (i.e., you can't load a component before it has an address space; you
//! can't run the shim before it's been loaded; you can't calculate the BootInfo
//! before the other components are in place, etc).

use super::cpu::Allocator;
use super::mem::{KvmUserspaceMemoryRegion, Region};
use super::VirtualMachine;

use crate::binary::{Component, Segment};

use crate::backend::kvm::shim::BootInfo;
use anyhow::Result;
use bounds::Line;
use kvm_ioctls::{Kvm, VmFd};
use memory::Page;
use x86_64::structures::paging::page_table::{PageTable, PageTableFlags};
use x86_64::{PhysAddr, VirtAddr};

use std::io;
use std::marker::PhantomData;
use std::num::NonZeroUsize;

// Marker structs for the typestate machine

/// An empty virtual machine
pub struct New;

/// A virtual machine with an address space
pub struct AddressSpace;

/// A virtual machine with a known CPU capacity
pub struct CpuCapacity;

/// A virtual machine whose BootInfo has been calculated
pub struct BootBlock;

/// A virtual machine with a shim loaded into it
pub struct Shim;

/// A virtual machine with user code loaded into it
pub struct Code;

/// Marker trait for the Builder states
pub trait State {}
impl State for New {}
impl State for AddressSpace {}
impl State for CpuCapacity {}
impl State for BootBlock {}
impl State for Shim {}
impl State for Code {}

/// Utility marker trait so states that are capable of
/// loading ELF binaries can share code.
pub trait Load {}
impl Load for BootBlock {}
impl Load for Shim {}

/// Constructing the virtual machine requires state to
/// be persistent and carried through to future construction
/// states. Fields are enclosed in `Option`s to simplify the
/// initial construction of the data because these fields are
/// set at different states.
struct Data {
    kvm: Option<Kvm>,
    fd: Option<VmFd>,
    /// Used for address translation between guest and host
    /// (also manages the lifetime of the backing host memory)
    address_space: Option<Region>,
    boot_info: Option<BootInfo>,
    max_cpus: Option<usize>,
    /// The shim's entry point
    shim_entry: Option<PhysAddr>,
}

pub struct Builder<T: State> {
    data: Data,
    _phantom: PhantomData<T>,
}

/// The initial state simply creates a KVM context.
impl Builder<New> {
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new()?;
        let fd = kvm.create_vm()?;
        Ok(Self {
            data: Data {
                kvm: Some(kvm),
                fd: Some(fd),
                address_space: None,
                boot_info: None,
                max_cpus: None,
                shim_entry: None,
            },
            _phantom: PhantomData,
        })
    }
}

/// A newly initialized Builder prepares the guest's address
/// space.
impl Builder<New> {
    pub fn with_max_cpus(
        mut self,
        max_cpus: NonZeroUsize,
    ) -> Result<Builder<CpuCapacity>, io::Error> {
        self.data.max_cpus = Some(max_cpus.get());

        Ok(Builder {
            data: self.data,
            _phantom: PhantomData,
        })
    }
}

impl Builder<CpuCapacity> {
    pub fn with_mem_size(mut self, mem_size: u64) -> Result<Builder<AddressSpace>, io::Error> {
        let guest_addr_start = unsafe {
            mmap::map(
                0,
                mem_size as _,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGE_2MB,
                None,
                0,
            )?
        };
        let unmap = unsafe {
            mmap::Unmap::new(bounds::Span {
                start: guest_addr_start,
                count: mem_size as _,
            })
        };
        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as _,
            userspace_addr: guest_addr_start as _,
        };

        let fd = self.data.fd.as_ref().unwrap();
        unsafe {
            fd.set_user_memory_region(region)?;
        }

        self.data.address_space = Some(Region::new(
            *self.data.max_cpus.as_ref().unwrap(),
            region,
            unmap,
        ));

        Ok(Builder {
            data: self.data,
            _phantom: PhantomData,
        })
    }
}

/// Once the guest's address space has been created, component
/// relocations can be calculated.
impl Builder<AddressSpace> {
    pub fn calculate_layout(
        mut self,
        shim_region: Line<usize>,
        code_region: Line<usize>,
    ) -> Result<Builder<BootBlock>, io::Error> {
        let addr_space = self.data.address_space.as_ref().unwrap();
        let memsz = addr_space.as_virt().count;

        let vm_setup = Line {
            start: 0,
            end: addr_space.prefix_mut().size(),
        };
        let boot_info = BootInfo::calculate(
            memsz as _,
            addr_space.as_virt().start.as_u64() as _,
            vm_setup,
            shim_region.into(),
            code_region.into(),
        )
        .map_err(|_| io::Error::from_raw_os_error(libc::ENOMEM))?;

        self.data.boot_info = Some(boot_info);

        Ok(Builder {
            data: self.data,
            _phantom: PhantomData,
        })
    }
}

/// Once component relocations have been calculated, we can load
/// the shim.
impl Builder<BootBlock> {
    pub fn load_shim(mut self, mut shim: Component) -> Result<Builder<Shim>, io::Error> {
        let offset = self.data.boot_info.as_ref().unwrap().shim.start;
        self.load_component(&mut shim, offset)?;
        self.data.shim_entry = Some(PhysAddr::new(shim.entry as _));

        Ok(Builder {
            data: self.data,
            _phantom: PhantomData,
        })
    }
}

/// Once the shim as been loaded, the code layer may be loaded.
impl Builder<Shim> {
    pub fn load_code(mut self, mut code: Component) -> Result<Builder<Code>, io::Error> {
        let offset = self.data.boot_info.as_ref().unwrap().code.start;
        self.load_component(&mut code, offset)?;

        Ok(Builder {
            data: self.data,
            _phantom: PhantomData,
        })
    }
}

impl<T: Load + State> Builder<T> {
    fn load_component(
        &mut self,
        component: &mut Component,
        offset: usize,
    ) -> Result<(), io::Error> {
        if component.pie {
            Self::relocate(component, offset);
        }

        self.load_segments(&component.segments)?;

        Ok(())
    }

    fn load_segments(&mut self, segs: &[Segment]) -> Result<(), io::Error> {
        let addr_space = self.data.address_space.as_ref().unwrap().as_virt();
        for seg in segs {
            let destination = {
                let raw = addr_space.start.as_u64() + seg.dst as u64;
                let addr = VirtAddr::new(raw);
                unsafe { std::slice::from_raw_parts_mut(addr.as_mut_ptr::<Page>(), seg.src.len()) }
            };

            destination.copy_from_slice(&seg.src[..]);
        }
        Ok(())
    }

    fn relocate(component: &mut Component, offset: usize) {
        component.entry += offset;

        for seg in &mut component.segments {
            seg.dst += offset;
        }
    }
}

/// Once both the shim and code have been loaded into the guest,
/// we can finally configure the dual-purpose bootinfo page and
/// prepare the startup vCPU.
impl Builder<Code> {
    pub fn build(self) -> Result<VirtualMachine, io::Error> {
        let boot_info = self.data.boot_info.unwrap();

        let vm = VirtualMachine {
            kvm: self.data.kvm.unwrap(),
            fd: self.data.fd.unwrap(),
            id_alloc: Allocator::new(),
            address_space: self.data.address_space.unwrap(),
            shim_entry: self.data.shim_entry.unwrap(),
            shim_start: PhysAddr::new(boot_info.shim.start as _),
        };

        let host_setup = vm.address_space.prefix_mut();
        host_setup.shared_pages[0] = Page::copy(boot_info);
        host_setup.shared_pages[1..]
            .iter_mut()
            .for_each(|page| *page = Page::default());
        *host_setup.zero = Page::default();
        *host_setup.pml4t = PageTable::new();
        *host_setup.pml3t_ident = PageTable::new();

        let addr_virt = vm.address_space.as_virt();
        let to_guest = |virt_addr| PhysAddr::new(virt_addr - addr_virt.start.as_u64());

        // Set up the page tables
        let pdpte = to_guest(&*host_setup.pml3t_ident as *const _ as u64);
        host_setup.pml4t[0].set_addr(pdpte, PageTableFlags::WRITABLE | PageTableFlags::PRESENT);
        host_setup.pml3t_ident[0].set_flags(
            PageTableFlags::HUGE_PAGE | PageTableFlags::WRITABLE | PageTableFlags::PRESENT,
        );

        Ok(vm)
    }
}
