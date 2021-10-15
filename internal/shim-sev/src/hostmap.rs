// SPDX-License-Identifier: Apache-2.0

//! Provides a mapping of the shim physical addresses to the hypervisor host virtual addresses,
//! needed for proxying syscalls.
//!
//! With the mapping the shim can construct a syscall for the kernel with the address
//! space of the host/hypervisor. Otherwise the hypervisor would have to translate
//! the shim physical addresses and would have to parse and understand
//! every syscall and correct the addresses.
//!
//! Because of memory ballooning (requesting more memory on demand) the hosts memory
//! is not contiguous and therefore we need a map for every memory region.
//!
//! ```text
//!                   Host             Shim
//!                  virtual          physical
//!    0x7fee0000  +--------+------>+--0x0000--+
//!                |        |       |          |
//!                |        |       |          |
//!                |        |       |          |
//!    0x7fee0400  +--------+---+-->+  0x0400  |        Payload
//!                             |   |          |        virtual
//!    0x3abb0000  +--------+---+   |          +<-----+---------+ 0x44450000
//!                |        |       |          |      |         |
//!                |        |       |          |      |         |
//!                |        |       |          |      |         |
//!                |        |   +-->+  0x0a00  |      |         |
//!                |        |   | | |          |      |         |
//!    0x3abb0600  +--------+---+ | |          |      |         |
//!                               | |          |      |         |
//!    0x5ccd0000  +--------+-----+ |          |      |         |
//!                |        |       |          |      |         |
//!                |        |       |          +<-----+---------+ 0x44450a00
//!                |        |       |          |
//!                |        |    +--+  0x1300  |
//!                |        |    |  |          |
//!                |        |    |  |          |
//!    0x5ccd0700  +--------+----+  |          |
//!                                 |          |
//!                                 |          |
//! ```

use crate::addr::HostVirtAddr;
use crate::print::PrintBarrier;
use crate::spin::RwLocked;

use core::alloc::Layout;
use core::mem::{align_of, size_of};

use linked_list_allocator::Heap;
use lset::{Line, Span};
use primordial::{Address, Page as Page4KiB};
use spinning::Lazy;
use x86_64::{PhysAddr, VirtAddr};

/// The global [`HostMap`](HostMap) RwLock
pub static HOSTMAP: Lazy<RwLocked<HostMap>> =
    Lazy::new(|| RwLocked::<HostMap>::new(HostMap::new()));

struct HostMemListPageHeader {
    next: Option<&'static mut HostMemListPage>,
}

/// A physical memory region with the corresponding host virtual start address
#[derive(Clone, Copy)]
struct HostMemEntry {
    shim: Span<PhysAddr, usize>,
    virt_start: VirtAddr,
}

/// Number of memory list entries per page
pub const HOST_MEM_LIST_NUM_ENTRIES: usize = (Page4KiB::SIZE
    - core::mem::size_of::<HostMemListPageHeader>())
    / core::mem::size_of::<HostMemEntry>();

struct HostMemListPage {
    header: HostMemListPageHeader,
    ent: [HostMemEntry; HOST_MEM_LIST_NUM_ENTRIES],
}

/// A mapping of the shim physical addresses to the hypervisor host virtual addresses
pub struct HostMap {
    num_pages: usize,
    end_of_mem: PhysAddr,
    host_mem: HostMemListPage,
}

impl HostMap {
    fn new() -> Self {
        HostMap {
            num_pages: 0,
            end_of_mem: PhysAddr::new(0),
            host_mem: HostMemListPage {
                header: HostMemListPageHeader { next: None },
                ent: [HostMemEntry {
                    shim: Span {
                        start: PhysAddr::new(0),
                        count: 0,
                    },
                    virt_start: VirtAddr::new(0),
                }; HOST_MEM_LIST_NUM_ENTRIES],
            },
        }
    }

    /// Get the host virtual address for a shim physical address
    fn get_virt_addr(&self, addr: PhysAddr) -> Option<VirtAddr> {
        let mut free = &self.host_mem;
        loop {
            for i in free.ent.iter() {
                if i.shim.count == 0 {
                    // Found an unused map entry
                    return None;
                }

                let line = Line::from(i.shim);

                if line.end > addr {
                    let offset = addr.as_u64().checked_sub(i.shim.start.as_u64()).unwrap();
                    return Some(i.virt_start + offset);
                }
            }
            match free.header.next {
                None => return None,
                Some(ref f) => free = *f,
            }
        }
    }
    fn do_extend_slots(&mut self, mem_slots: usize, allocator: &mut Heap) {
        // Allocate enough pages to hold all memory slots in advance
        // There is already one HostMemListPage present, so we can ignore the rest of the division.
        let num_pages = mem_slots.checked_div(HOST_MEM_LIST_NUM_ENTRIES).unwrap();

        if self.num_pages >= num_pages {
            return;
        }

        let mut last_page = &mut self.host_mem as *mut HostMemListPage;

        for _i in 0..num_pages {
            unsafe {
                last_page = match (*last_page).header.next {
                    None => {
                        let new_page = {
                            let page_res = allocator.allocate_first_fit(
                                Layout::from_size_align(
                                    size_of::<HostMemListPage>(),
                                    align_of::<HostMemListPage>(),
                                )
                                .unwrap(),
                            );

                            if page_res.is_err() {
                                return;
                            }

                            let page: *mut HostMemListPage = page_res.unwrap().as_ptr() as _;

                            page.write_bytes(0, 1);
                            page
                        };

                        (*last_page).header.next = Some(&mut *new_page);
                        self.num_pages = self.num_pages.checked_add(1).unwrap();
                        new_page
                    }
                    Some(ref mut p) => *p as *mut _,
                };
            }
        }
    }
}

impl RwLocked<HostMap> {
    /// Extend the number of slots in the map
    pub fn extend_slots(&self, mem_slots: usize, allocator: &mut Heap) {
        // While updating the HostMap the syscall proxying can't be used,
        // so disable any debug printing possibly happening while allocating
        // memory in `inner_extend_slots`.
        //
        // Dropping the `_barrier` will re-enable printing.
        let _barrier = PrintBarrier::default();

        self.write().do_extend_slots(mem_slots, allocator);
    }

    /// Translate a shim physical unencrypted address to a host virtual address
    pub fn shim_phys_to_host_virt<U>(&self, shim_phys: PhysAddr) -> HostVirtAddr<U> {
        let this = self.read();

        let virt_addr = this.get_virt_addr(shim_phys).unwrap_or_else(|| {
            panic!(
                "Trying to get virtual offset from unmmapped location {:#?}",
                shim_phys
            )
        });

        unsafe { HostVirtAddr::new(Address::<u64, U>::unchecked(virt_addr.as_u64() as _)) }
    }

    /// set the initial map entry
    pub fn first_entry(&self, vm_phys: PhysAddr, host_virt: VirtAddr, size: usize) {
        let mut this = self.write();
        this.host_mem.ent[0].shim.start = vm_phys;
        this.host_mem.ent[0].shim.count = size;
        this.host_mem.ent[0].virt_start = host_virt;
        this.end_of_mem = vm_phys + size;
    }

    /// Add a new map entry
    pub fn new_entry(
        &self,
        vm_phys: PhysAddr,
        host_virt: VirtAddr,
        size: usize,
    ) -> Option<Span<PhysAddr, usize>> {
        let mut this = self.write();

        let vm_line = Line::from(Span::new(vm_phys, size));

        let old_max = this.end_of_mem;
        this.end_of_mem = PhysAddr::new(u64::max(this.end_of_mem.as_u64(), vm_line.end.as_u64()));

        let mut free = &mut this.host_mem;

        loop {
            for i in free.ent.iter_mut() {
                if i.shim.count == 0 {
                    i.virt_start = host_virt;
                    i.shim.start = vm_phys;
                    i.shim.count = size;
                    return Some(i.shim);
                }
            }

            // we have reached the end of the free slot page
            // advance to the next page
            if let Some(f) = free.header.next.as_mut() {
                free = f;
            } else {
                // restore the old value in case of the unlikely error case
                this.end_of_mem = old_max;
                return None;
            }
        }
    }

    /// Return the first unused physical address
    pub fn end_of_mem(&self) -> PhysAddr {
        self.read().end_of_mem
    }
}
