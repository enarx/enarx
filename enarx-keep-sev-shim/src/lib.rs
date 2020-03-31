// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
#![cfg_attr(not(all(not(feature = "nightly"), test)), no_std)]
#![cfg_attr(all(feature = "nightly", test), no_main)]
#![cfg_attr(feature = "nightly", feature(custom_test_frameworks))]
#![cfg_attr(feature = "nightly", feature(abi_x86_interrupt))]
#![cfg_attr(feature = "nightly", feature(alloc_error_handler))]
#![cfg_attr(feature = "nightly", test_runner(crate::test_runner))]
#![cfg_attr(feature = "nightly", feature(lang_items))]
#![cfg_attr(feature = "nightly", reexport_test_harness_main = "test_main")]
#![allow(clippy::empty_loop)]
#![deny(missing_docs)]
// FIXME: https://github.com/enarx/enarx/issues/391
#![allow(missing_docs)]

#[cfg(feature = "allocator")]
extern crate alloc;

#[cfg(feature = "allocator")]
use linked_list_allocator::LockedHeap;

#[cfg(any(not(test), feature = "nightly"))]
pub mod arch;
#[cfg(all(any(not(test), feature = "nightly"), not(feature = "qemu")))]
pub mod libc;
#[cfg(any(not(test), feature = "nightly"))]
pub mod memory;
#[cfg(any(not(test), feature = "nightly"))]
pub mod strlen;
#[cfg(any(not(test), feature = "nightly"))]
pub mod syscall;

#[cfg(feature = "nightly")]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {
    exit_hypervisor(HyperVisorExitCode::Failed);
}

#[cfg(all(not(feature = "nightly"), not(test)))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {
    exit_hypervisor(HyperVisorExitCode::Failed);
}

#[cfg(any(not(test), feature = "nightly"))]
#[no_mangle]
extern "C" fn _Unwind_Resume() {
    exit_hypervisor(HyperVisorExitCode::Failed);
}

#[cfg(feature = "allocator")]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

extern "C" {
    fn _context_switch(entry_point: extern "C" fn() -> !, stack_pointer: usize) -> !;
}

#[cfg(feature = "nightly")]
pub fn test_runner(tests: &[&dyn Fn()]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    exit_hypervisor(HyperVisorExitCode::Success);
}

#[cfg(feature = "nightly")]
pub fn test_panic_handler(info: &core::panic::PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HyperVisorExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_hypervisor(exit_code: HyperVisorExitCode) {
    use x86_64::instructions::port::PortWriteOnly;

    unsafe {
        let mut port = PortWriteOnly::new(0xf4);
        port.write(exit_code as u32);
    }
}

pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[cfg(all(test, feature = "nightly"))]
entry_point!(test_lib_main);

/// Entry point for `cargo xtest`
#[cfg(all(test, feature = "nightly"))]
fn test_lib_main(boot_info: &'static mut vmsyscall::bootinfo::BootInfo) -> ! {
    use crate::arch::OffsetPageTable;
    use crate::memory::BootInfoFrameAllocator;

    fn inner(
        _mapper: &mut OffsetPageTable,
        _frame_allocator: &mut BootInfoFrameAllocator,
        _app_entry_point: *const u8,
        _app_load_addr: *const u8,
        _app_phnum: usize,
    ) -> ! // trigger a stack overflow
    {
        test_main();
        hlt_loop();
    }
    //println!("{}:{} test_lib_main", file!(), line!());

    crate::arch::init(boot_info, inner);
}

#[cfg(all(test, feature = "nightly"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    test_panic_handler(info)
}

#[cfg(feature = "allocator")]
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
