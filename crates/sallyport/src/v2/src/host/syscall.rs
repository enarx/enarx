// SPDX-License-Identifier: Apache-2.0

use super::Execute;
use crate::{item, read_first, Result};

use core::arch::asm;
use core::ptr::NonNull;
use libc::c_long;

struct Syscall<const ARGS: usize, const RETS: usize> {
    /// The syscall number for the request.
    ///
    /// See, for example, [`libc::SYS_exit`](libc::SYS_exit).
    num: c_long,

    /// The syscall argument vector.
    argv: [usize; ARGS],

    /// Return values.
    ret: *mut [usize; RETS],
}

impl Execute for Syscall<0, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<1, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        in("rdi") self.argv[0],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<2, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<3, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<4, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<5, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        in("r8") self.argv[4],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<6, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => (*self.ret)[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        in("r8") self.argv[4],
        in("r9") self.argv[5],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

pub(super) unsafe fn execute_syscall(ptr: NonNull<(item::Syscall, [u8])>) -> Result<()> {
    let (num, ptr) = read_first(ptr.cast());
    match num as _ {
        libc::SYS_exit => {
            let (status, ptr) = read_first(NonNull::new_unchecked(ptr));
            Syscall {
                num: libc::SYS_exit,
                argv: [status],
                ret: ptr.add(5) as _,
            }
            .execute()
        }
        _ => return Err(libc::ENOSYS),
    }
    Ok(())
}
