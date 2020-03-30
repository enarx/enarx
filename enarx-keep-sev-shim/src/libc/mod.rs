// SPDX-License-Identifier: Apache-2.0

use vmsyscall::{ErrNo, VmSyscall, VmSyscallRet, WRITE_BUF_LEN};
use x86_64::instructions::port::Port;
use x86_64::VirtAddr;

mod mmap;
pub use mmap::*;

use crate::arch::{SYSCALL_PHYS_ADDR, SYSCALL_TRIGGER_PORT};

#[cfg(all(test, feature = "nightly"))]
mod test;

#[inline(always)]
pub fn write(fd: u32, bytes: &[u8]) -> Result<i32, ErrNo> {
    unsafe {
        let syscall_page = VirtAddr::new(SYSCALL_PHYS_ADDR);
        let request = syscall_page.as_u64() as *mut VmSyscall;
        let mut data = [0u8; WRITE_BUF_LEN];
        data[..bytes.len()].copy_from_slice(bytes);

        request.write_volatile(VmSyscall::Write {
            fd,
            count: bytes.len(),
            data,
        });

        let mut port = Port::<u16>::new(SYSCALL_TRIGGER_PORT);
        port.write(1 as u16);
        let reply = syscall_page.as_u64() as *mut VmSyscallRet;

        match reply.read_volatile() {
            VmSyscallRet::Write(res) => res,
            _ => panic!("Unknown KvmSyscallRet"),
        }
    }
}

#[inline(always)]
pub fn vm_syscall(syscall: VmSyscall) -> Result<VmSyscallRet, ErrNo> {
    let syscall_page = VirtAddr::new(unsafe { SYSCALL_PHYS_ADDR });
    let request = syscall_page.as_u64() as *mut VmSyscall;
    let reply = syscall_page.as_u64() as *mut VmSyscallRet;

    unsafe {
        request.write_volatile(syscall);
        let mut port = Port::<u16>::new(SYSCALL_TRIGGER_PORT);
        port.write(1 as u16);
        Ok(reply.read_volatile())
    }
}

#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum c_void {
    #[doc(hidden)]
    __variant1,
    #[doc(hidden)]
    __variant2,
}
