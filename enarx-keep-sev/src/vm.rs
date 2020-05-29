// SPDX-License-Identifier: Apache-2.0

use crate::x86_64::*;

use std::io;

use kvm_bindings::kvm_userspace_memory_region as MemoryRegion;
use kvm_ioctls::{Kvm, VmFd};
use x86_64::structures::paging::page_table::PageTableFlags;
use x86_64::VirtAddr;

const DEFAULT_MEM_SIZE: usize = units::bytes!(1; GiB);

pub struct VirtualMachine {
    _kvm: Kvm,
    _fd: VmFd,
    _address_space: Vec<MemoryRegion>,
    _mmap_handles: Vec<mmap::Unmap>,
}

impl VirtualMachine {
    pub fn new() -> Result<Self, io::Error> {
        // Create a KVM context
        let kvm = Kvm::new()?;
        let fd = kvm.create_vm()?;

        // Create the guest address space
        let mem_size = DEFAULT_MEM_SIZE; // Just use a default size for now.
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
            mmap::Unmap::new(span::Span {
                start: guest_addr_start,
                count: mem_size,
            })
        };
        let region = MemoryRegion {
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

        Ok(Self {
            _kvm: kvm,
            _fd: fd,
            _address_space: vec![region],
            _mmap_handles: vec![unmap],
        })
    }
}
