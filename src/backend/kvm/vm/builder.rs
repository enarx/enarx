// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::backend::kvm::shim::BootInfo;
use crate::binary::Component;
use crate::sallyport::Block;

use anyhow::Result;
use kvm_ioctls::{Kvm, VmFd};
use lset::{Line, Span};
use mmarinus::{perms, Kind, Map};
use nbytes::bytes;
use primordial::Page;
use x86_64::structures::paging::page_table::{PageTable, PageTableFlags};
use x86_64::{align_up, PhysAddr, VirtAddr};

use std::mem::{align_of, size_of};

/// The first part of the setup area of the VM
///
/// - The first page is a zero page.
/// - The page tables follow the zero page.
#[repr(C, align(4096))]
pub struct SetupRegionPre {
    zero_page: Page,
    pml4t: PageTable,
    pml3t_ident: PageTable,
}

/// The setup area of the VM
///
/// The address space needs to be laid out in a way that the shim
/// is expecting. This means that:
/// - The first page is a zero page.
/// - The page tables follow the zero page.
/// - The rest of the `MAX_SETUP_SIZE` bytes is consumed by an
///   array of [`sallyport::Block`](crate::sallyport::Block)
/// - The first shared [`sallyport::Block`](crate::sallyport::Block)
///   contains the [`BootInfo`](crate::backend::kvm::shim::BootInfo) struct at start.
///   The [`BootInfo`](crate::backend::kvm::shim::BootInfo)
///   struct communicates other important values to the shim.
#[repr(C, align(4096))]
pub struct SetupRegion {
    pre: SetupRegionPre,
    syscall_blocks: [Block; N_SYSCALL_BLOCKS],
}

pub const N_SYSCALL_BLOCKS: usize =
    (MAX_SETUP_SIZE - size_of::<SetupRegionPre>()) / size_of::<Block>();

/// A functor type that receives a target address as its first input,
/// a base/memory region starting address as its second input, and it
/// returns the guest physical address that corresponds to the target
/// address.
///
/// Implementors may choose to override this so that they can enable
/// certain bits in the resulting physical address (i.e., SEV memory
/// encryption).
pub type Hv2GpFn = dyn Fn(VirtAddr, VirtAddr) -> PhysAddr;

pub trait Hook {
    fn shim_loaded(&mut self, _vm: &mut VmFd, _addr_space: &[u8]) -> Result<()> {
        Ok(())
    }

    fn code_loaded(
        &mut self,
        _vm: &mut VmFd,
        _saddr_space: &[u8],
        _syscall_blocks: VirtAddr,
    ) -> Result<()> {
        Ok(())
    }

    fn measure(&mut self, _vm: &mut VmFd, _saddr_space: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn hv2gp(&self) -> Box<Hv2GpFn> {
        Box::new(|target, start| PhysAddr::new(target.as_u64() - start.as_u64()))
    }
}

pub struct Builder<T: Hook> {
    hook: T,
    shim: Component,
    code: Component,
}

struct Arch {
    syscall_blocks: VirtAddr,
    cr3: PhysAddr,
}

#[allow(dead_code)]
enum BuildOrMeasure {
    Build,
    Measure,
}

impl<T: Hook> Builder<T> {
    pub fn new(shim: Component, code: Component, hook: T) -> Self {
        Self { shim, code, hook }
    }

    fn build_or_measure(mut self, bor: BuildOrMeasure) -> Result<Option<Vm>> {
        let kvm = Kvm::new()?;
        let mut fd = kvm.create_vm()?;

        let mut boot_info =
            Self::calculate_setup_region(self.shim.region().into(), self.code.region().into())?;

        let mem_size = align_up(boot_info.mem_size as _, bytes![2; MiB]);
        // fill out remaining fields of `BootInfo`
        boot_info.nr_syscall_blocks = N_SYSCALL_BLOCKS;
        boot_info.mem_size = mem_size as _;
        let (map, region) = Self::allocate_address_space(mem_size as _)?;
        unsafe { fd.set_user_memory_region(region)? };

        let arch = self.arch_specific_setup(&map, &boot_info);

        let addr = VirtAddr::new(map.addr() as u64);
        let shim_start = boot_info.shim.start;
        Self::load_component(addr, &mut self.shim, shim_start);
        let shim_entry = PhysAddr::new(self.shim.entry as _);
        self.hook.shim_loaded(&mut fd, &map)?;

        let code_offset = boot_info.code.start;
        Self::load_component(addr, &mut self.code, code_offset);

        match bor {
            BuildOrMeasure::Measure => {
                self.hook.measure(&mut fd, &map)?;
                Ok(None)
            }

            BuildOrMeasure::Build => {
                self.hook.code_loaded(&mut fd, &map, arch.syscall_blocks)?;

                let vm = Vm {
                    kvm,
                    fd,
                    regions: vec![Region::new(region, map)],
                    syscall_start: arch.syscall_blocks,
                    hv2gp: self.hook.hv2gp(),
                    shim_entry,
                    shim_start: PhysAddr::new(shim_start as _),
                    cr3: arch.cr3,
                };

                Ok(Some(vm))
            }
        }
    }

    pub fn build(self) -> Result<Vm> {
        self.build_or_measure(BuildOrMeasure::Build)
            .map(|o| o.unwrap())
    }

    #[allow(dead_code)]
    pub fn measure(self) -> Result<()> {
        self.build_or_measure(BuildOrMeasure::Measure).map(|_| ())
    }

    fn calculate_setup_region(shim_size: Span<usize>, code_size: Span<usize>) -> Result<BootInfo> {
        let setup_size = Line {
            start: 0,
            end: size_of::<SetupRegion>(),
        };

        let boot_info = BootInfo::calculate(setup_size, shim_size, code_size)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;

        Ok(boot_info)
    }

    fn allocate_address_space(
        mem_size: usize,
    ) -> Result<(Map<perms::ReadWrite>, KvmUserspaceMemoryRegion)> {
        let map = Map::map(mem_size)
            .anywhere()
            .anonymously()
            .known::<perms::ReadWrite>(Kind::Private)?;

        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as _,
            userspace_addr: map.addr() as _,
        };

        let res = (map, region);

        Ok(res)
    }

    fn arch_specific_setup(&mut self, map: &Map<perms::ReadWrite>, boot_info: &BootInfo) -> Arch {
        use PageTableFlags as Flags;

        // This assumes all the bytes in `map` are initialized with zero, which
        // is normally the case with MAP_ANONYMOUS
        debug_assert!(map.size() >= size_of::<SetupRegion>());
        debug_assert_eq!(map.addr() % align_of::<SetupRegion>(), 0);
        let setup = unsafe { &mut *(map.addr() as *mut SetupRegion) };
        let hv2gp = self.hook.hv2gp();

        unsafe {
            std::ptr::copy_nonoverlapping(
                boot_info,
                &mut setup.syscall_blocks[0] as *mut Block as _,
                1,
            );
        }

        let pml3t_ident_addr = VirtAddr::new(&setup.pre.pml3t_ident as *const _ as u64);
        let start = VirtAddr::new(map.addr() as u64);
        let pdpte = hv2gp(pml3t_ident_addr, start);
        setup.pre.pml4t[0].set_addr(pdpte, Flags::WRITABLE | Flags::PRESENT);

        let pml3t_addr = hv2gp(start, start);
        let flags = Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT;
        setup.pre.pml3t_ident[0].set_addr(pml3t_addr, flags);

        let pml4t = VirtAddr::new(&setup.pre.pml4t as *const _ as _);

        let cr3 = hv2gp(pml4t, start);
        let syscall_blocks = VirtAddr::from_ptr(setup.syscall_blocks.as_ptr());

        // The information returned here is used by the KVM VM during runtime
        // to create vCPUs.
        Arch {
            syscall_blocks,
            cr3,
        }
    }

    fn load_component(start: VirtAddr, component: &mut Component, offset: usize) {
        use std::slice::from_raw_parts_mut;

        if component.pie {
            component.entry += offset;
            for seg in &mut component.segments {
                seg.dst += offset;
            }
        }

        for seg in &component.segments {
            let dst = VirtAddr::new(seg.dst as u64 + start.as_u64());
            let dst = unsafe { from_raw_parts_mut(dst.as_mut_ptr::<Page>(), seg.src.len()) };
            dst.copy_from_slice(&seg.src[..]);
        }
    }
}
