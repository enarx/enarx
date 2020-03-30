// SPDX-License-Identifier: Apache-2.0

#[macro_use]
pub mod serial;

pub mod gdt;

pub mod idt;
pub mod interrupts;

mod start_e820;

pub mod structures;
pub mod syscall;

#[cfg(feature = "timer")]
pub mod timer;

mod exec;
pub use exec::exec_elf;

mod init;
pub use init::init;

pub mod pagetables;

mod mmap;
pub use mmap::{brk_user, mmap_user};

mod xcr0;

use crate::arch::x86_64::structures::paging::OffsetPageTable;
use crate::memory::BootInfoFrameAllocator;
pub use x86_64::{PhysAddr, VirtAddr};

/// Defines the entry point function.
///
/// The function must have the signature `fn(&'static BootInfo) -> !`.
///
/// This macro just creates a function named `_start`, which the linker will use as the entry
/// point. The advantage of using this macro instead of providing an own `_start` function is
/// that the macro ensures that the function and argument types are correct.
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        #[export_name = "_start_main"]
        pub extern "C" fn __impl_start(boot_info: &'static mut vmsyscall::bootinfo::BootInfo) -> ! {
            // validate the signature of the program entry point
            let f: fn(&'static mut vmsyscall::bootinfo::BootInfo) -> ! = $path;
            f(boot_info)
        }
    };
}

pub const PAGESIZE: usize = 4096;
pub const STACK_START: usize = 0x7F48_4800_0000;
pub const STACK_SIZE: usize = 1024 * 1024; // 1 MiB

static mut APP_ENTRY_POINT: *const u8 = core::ptr::null();
static mut APP_LOAD_ADDR: *const u8 = core::ptr::null();
static mut APP_PH_NUM: usize = 0;
static mut FRAME_ALLOCATOR: Option<BootInfoFrameAllocator> = None;
static mut MAPPER: Option<OffsetPageTable> = None;

// TODO: multi-thread or syscall-proxy
pub static mut NEXT_MMAP: u64 = 0;

#[cfg(feature = "allocator")]
pub const HEAP_START: usize = 0x7F4E_4300_0000;
#[cfg(feature = "allocator")]
pub const HEAP_SIZE: usize = 1 * 1024 * 1024; // 1 MiB
