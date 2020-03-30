// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{exec_elf, init, serial, structures::paging::OffsetPageTable};

pub static mut SYSCALL_PHYS_ADDR: u64 = 0;
pub static mut SYSCALL_TRIGGER_PORT: u16 = 0;

pub fn init_syscall(boot_info: &vmsyscall::bootinfo::BootInfo) {
    unsafe {
        SYSCALL_PHYS_ADDR = boot_info as *const vmsyscall::bootinfo::BootInfo as _;
        SYSCALL_TRIGGER_PORT = boot_info.syscall_trigger_port;
    }
}
