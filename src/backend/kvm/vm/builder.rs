// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::backend::kvm::shim::BootInfo;

use crate::binary::Component;

use anyhow::Result;
use kvm_ioctls::{Kvm, VmFd};
use lset::{Line, Span};
use mmarinus::{perms, Kind, Map};
use nbytes::bytes;
use primordial::Page;
use x86_64::structures::paging::page_table::{PageTable, PageTableFlags};
use x86_64::{align_up, PhysAddr, VirtAddr};

use std::mem::size_of;
use std::num::NonZeroUsize;

// It is convenient and cheap to provision up to a maximum
// thread count.
const DEFAULT_MAX_CPU: usize = 256;

pub struct Config {
    pub n_syscall_pages: NonZeroUsize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            n_syscall_pages: NonZeroUsize::new(DEFAULT_MAX_CPU).unwrap(),
        }
    }
}

pub trait Hook {
    fn shim_loaded(&mut self, _vm: &mut VmFd, _addr_space: &[u8]) -> Result<()> {
        Ok(())
    }

    fn code_loaded(&mut self, _vm: &mut VmFd, _addr_space: &[u8]) -> Result<()> {
        Ok(())
    }

    fn to_guest_phys(&self, addr: VirtAddr, start: VirtAddr) -> PhysAddr {
        PhysAddr::new(addr.as_u64() - start.as_u64())
    }
}

pub struct Builder<T: Hook> {
    hook: T,
    shim: Component,
    code: Component,
    config: Config,
}

struct Arch {
    syscall_pages: VirtAddr,
    cr3: PhysAddr,
}

impl<T: Hook> Builder<T> {
    pub fn new(config: Config, shim: Component, code: Component, hook: T) -> Self {
        Self {
            config,
            shim,
            code,
            hook,
        }
    }
    pub fn build(mut self) -> Result<Vm> {
        let kvm = Kvm::new()?;
        let mut fd = kvm.create_vm()?;

        let boot_info = Self::calculate_setup_region(
            &self.config,
            self.shim.region().into(),
            self.code.region().into(),
        )?;

        let mem_size = align_up(boot_info.mem_size as _, bytes![2; MiB]);
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
        self.hook.code_loaded(&mut fd, &map)?;

        let vm = Vm {
            kvm,
            fd,
            regions: vec![Region::new(region, map)],
            syscall_start: arch.syscall_pages,
            shim_entry,
            shim_start: PhysAddr::new(shim_start as _),
            cr3: arch.cr3,
        };

        Ok(vm)
    }

    fn calculate_setup_region(
        cfg: &Config,
        shim_size: Span<usize>,
        code_size: Span<usize>,
    ) -> Result<BootInfo> {
        let setup_size = Page::size()
            + (Page::size() * cfg.n_syscall_pages.get())
            + size_of::<PageTable>()
            + size_of::<PageTable>();

        let setup_size = Line {
            start: 0,
            end: setup_size,
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

        let syscall_start;
        let pml3t_ident;
        let pml4t;
        let zero;

        // The address space needs to be laid out in a way that the shim
        // is expecting. This means that:
        //
        //  - The first page is a zero page.
        //  - The N pages after the zero page are shared syscall pages.
        //      - The first shared syscall page contains the BootInfo
        //        struct. The BootInfo struct communicates other important
        //        values to the shim.
        //  - The page tables follow the syscall pages.
        unsafe {
            let mut setup = VirtAddr::new(map.addr() as _);
            // First page is zero page
            zero = &mut *setup.as_mut_ptr::<Page>();
            *zero = Page::default();
            setup += size_of::<Page>();

            // First shared syscall page gets a copy of the BootInfo struct
            *setup.as_mut_ptr::<BootInfo>() = *boot_info;
            syscall_start = setup;
            setup += size_of::<Page>();

            // Rest of the shared syscall pages should be zeroed
            for _ in 1..self.config.n_syscall_pages.get() {
                *setup.as_mut_ptr::<Page>() = Page::default();
                setup += size_of::<Page>();
            }

            // Set up page tables
            *setup.as_mut_ptr::<PageTable>() = PageTable::new();
            pml4t = &mut *setup.as_mut_ptr::<PageTable>();
            setup += size_of::<PageTable>();

            *setup.as_mut_ptr::<PageTable>() = PageTable::new();
            pml3t_ident = &mut *setup.as_mut_ptr::<PageTable>();
            setup += size_of::<PageTable>();
        }

        let pml3t_ident_addr = VirtAddr::new(pml3t_ident as *const _ as u64);
        let start = VirtAddr::new(map.addr() as u64);
        let pdpte = self.hook.to_guest_phys(pml3t_ident_addr, start);
        pml4t[0].set_addr(pdpte, Flags::WRITABLE | Flags::PRESENT);

        let pml3t_addr = self.hook.to_guest_phys(start, start);
        let flags = Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT;
        pml3t_ident[0].set_addr(pml3t_addr, flags);

        let syscall_pages = unsafe {
            std::slice::from_raw_parts_mut(
                syscall_start.as_mut_ptr::<Page>(),
                self.config.n_syscall_pages.get(),
            )
        };

        let pml4t = VirtAddr::new(pml4t as *const _ as _);
        let cr3 = self.hook.to_guest_phys(pml4t, start);

        // The information returned here is used by the KVM VM during runtime
        // to create vCPUs.
        Arch {
            syscall_pages: VirtAddr::new(&syscall_pages[0] as *const _ as _),
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
