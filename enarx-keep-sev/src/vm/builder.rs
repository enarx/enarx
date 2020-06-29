// SPDX-License-Identifier: Apache-2.0

use super::mem::{KvmUserspaceMemoryRegion, Region};
use super::VirtualMachine;

use crate::x86_64::*;
use kvm_ioctls::Kvm;
use loader::segment::Segment;
use loader::Component;
use memory::Page;
use x86_64::structures::paging::page_table::PageTableFlags;
use x86_64::VirtAddr;

use std::io;

const DEFAULT_MEM_SIZE: usize = units::bytes!(1; GiB);

pub struct Builder {
    vm: VirtualMachine,
}

impl Builder {
    pub fn new() -> Result<Self, io::Error> {
        let kvm = Kvm::new()?;
        let fd = kvm.create_vm()?;

        let mem_size = DEFAULT_MEM_SIZE;
        let guest_addr_start = unsafe {
            mmap::map(
                0,
                mem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGE_2MB,
                None,
                0,
            )?
        };
        let unmap = unsafe {
            mmap::Unmap::new(bounds::Span {
                start: guest_addr_start,
                count: mem_size,
            })
        };
        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as _,
            userspace_addr: guest_addr_start as _,
        };

        unsafe {
            fd.set_user_memory_region(region)?;
        }

        // Set up the page tables
        let mut page_tables = PageTables::default();
        let pdpte = PDPTE_START;
        page_tables.pml4t[0].set_addr(pdpte, PageTableFlags::WRITABLE | PageTableFlags::PRESENT);

        page_tables.pml3t_ident[0].set_flags(
            PageTableFlags::HUGE_PAGE | PageTableFlags::WRITABLE | PageTableFlags::PRESENT,
        );

        // Install the page tables into the guest address space
        unsafe {
            VirtAddr::new(region.userspace_addr + PML4_START.as_u64())
                .as_mut_ptr::<PageTables>()
                .write(page_tables);
        }

        let vm = VirtualMachine {
            _kvm: kvm,
            _fd: fd,
            address_space: Region::new(region, unmap),
        };

        Ok(Self { vm })
    }

    pub fn load(&mut self, component: &Component) -> Result<VirtAddr, io::Error> {
        self.load_segments(&component.segments)?;

        let addr_space = self.vm.address_space.as_virt();
        Ok(VirtAddr::new(
            addr_space.start.as_u64() + component.entry as u64,
        ))
    }

    fn load_segments(&mut self, segs: &[Segment]) -> Result<(), io::Error> {
        let addr_space = self.vm.address_space.as_virt();
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

    pub fn build(self) -> VirtualMachine {
        self.vm
    }
}
