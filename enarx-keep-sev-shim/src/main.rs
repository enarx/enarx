// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
#![cfg_attr(not(all(not(feature = "nightly"), test)), no_std)]
#![cfg_attr(not(all(not(feature = "nightly"), test)), no_main)]
#![warn(dead_code)]
#![cfg_attr(feature = "nightly", feature(custom_test_frameworks))]
#![cfg_attr(feature = "nightly", test_runner(enarx_keep_sev_shim::test_runner))]
#![cfg_attr(feature = "nightly", reexport_test_harness_main = "test_main")]
#![allow(clippy::empty_loop)]
#![deny(missing_docs)]
// FIXME: https://github.com/enarx/enarx/issues/391
#![allow(missing_docs)]

#[cfg(any(not(test), all(test, feature = "nightly")))]
enarx_keep_sev_shim::entry_point!(kernel_main);

#[cfg(not(test))]
fn kernel_main(boot_info: &'static mut vmsyscall::bootinfo::BootInfo) -> ! {
    use enarx_keep_sev_shim::arch::{self, OffsetPageTable};
    use enarx_keep_sev_shim::memory::BootInfoFrameAllocator;

    fn with_stack_protection(
        mapper: &mut OffsetPageTable,
        frame_allocator: &mut BootInfoFrameAllocator,
        app_entry_point: *const u8,
        app_load_addr: *const u8,
        app_phnum: usize,
    ) -> ! {
        arch::exec_elf(
            mapper,
            frame_allocator,
            app_entry_point,
            app_load_addr,
            app_phnum,
        );
    }
    enarx_keep_sev_shim::arch::init(boot_info, with_stack_protection)
}

#[cfg(all(test, feature = "nightly"))]
fn kernel_main(boot_info: &'static mut vmsyscall::bootinfo::BootInfo) -> ! {
    use enarx_keep_sev_shim::arch::{self, OffsetPageTable};
    use enarx_keep_sev_shim::memory::BootInfoFrameAllocator;
    use enarx_keep_sev_shim::{exit_hypervisor, println, HyperVisorExitCode};

    fn inner(
        _mapper: &mut OffsetPageTable,
        _frame_allocator: &mut BootInfoFrameAllocator,
        _app_entry_point: *const u8,
        _app_load_addr: *const u8,
        _app_phnum: usize,
    ) -> ! {
        test_main();
        println!("It did not crash!");
        exit_hypervisor(HyperVisorExitCode::Success);
        enarx_keep_sev_shim::hlt_loop()
    }

    arch::init(boot_info, inner)
}

/// This function is called on panic.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use enarx_keep_sev_shim::{exit_hypervisor, println, HyperVisorExitCode};
    println!("{}", info);
    exit_hypervisor(HyperVisorExitCode::Failed);
    enarx_keep_sev_shim::hlt_loop()
}

#[cfg(all(test, feature = "nightly"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    enarx_keep_sev_shim::test_panic_handler(info)
}

#[cfg(all(test, not(feature = "nightly")))]
fn main() {}
