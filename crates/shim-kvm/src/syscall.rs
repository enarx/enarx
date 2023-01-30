// SPDX-License-Identifier: Apache-2.0

//! syscall interface layer between assembler and rust
#![allow(non_upper_case_globals)]

use crate::hostcall::{HostCall, UserMemScope};
use crate::thread::{pickup_new_threads, TcbRefCell};

use core::arch::global_asm;
use core::mem::size_of;

use sallyport::guest::Handler;
use sallyport::item::enarxcall::{SYS_GETATT, SYS_GETKEY};
use sallyport::libc::SYS_exit;
#[cfg(feature = "dbg")]
use sallyport::libc::{SYS_write, STDERR_FILENO, STDOUT_FILENO};
use x86_64::VirtAddr;

#[repr(C)]
struct X8664DoubleReturn {
    rax: u64,
    rdx: u64,
}

extern "sysv64" {
    /// syscall service routine
    ///
    /// # Safety
    ///
    /// This function is not be called from rust.
    #[cfg_attr(coverage, no_coverage)]
    pub fn _syscall_enter() -> !;
}
// offset Tcb.kernel_stack
const KERNEL_RSP_OFF: usize = 0;
// offset Tcb.userspace_stack
const USR_RSP_OFF: usize = size_of::<VirtAddr>();
global_asm!(
        ".pushsection .text.syscall_enter,\"ax\",@progbits",
        ".global _syscall_enter",
        "_syscall_enter:",

        // prepare the stack for sysretq and load the kernel rsp
        "swapgs",                                           // set gs segment to TSS

        // swapgs variant of Spectre V1. Disable speculation past this point
        "lfence",

        "mov    QWORD PTR gs:{USR},     rsp",               // save userspace rsp
        "mov    rsp,                    QWORD PTR gs:{KRN}",// load kernel rsp
        "push   QWORD PTR gs:{USR}",                        // push userspace rsp - stack_pointer_ring_3
        "mov    QWORD PTR gs:{USR},     0x0",               // clear userspace rsp in the Tcb
        "push   r11",                                       // push RFLAGS stored in r11
        "push   rcx",                                       // push userspace return pointer
        "push   rbp",
        "mov    rbp,                    rsp",               // Save stack frame

        // Arguments in registers:
        // SYSV:    rdi, rsi, rdx, rcx, r8, r9
        // SYSCALL: rdi, rsi, rdx, r10, r8, r9 and syscall number in rax
        "mov    rcx,                    r10",

        // save registers
        "push   rdi",
        "push   rsi",
        "push   rdx",
        "push   rbx",
        "push   r15",
        "push   r14",
        "push   r13",
        "push   r12",
        "push   r10",
        "push   r9",
        "push   r8",

        "push   rax",                                       // syscall number on the stack as the eighth argument
        "push   rsp",                                       // stack frame pointer on the stack as the seventh argument

        "call   {syscall_rust}",

        "add    rsp,                    0x10",              // skip rax pop, as it is the return value

        // restore registers
        "pop    r8",
        "pop    r9",
        "pop    r10",
        "pop    r12",
        "pop    r13",
        "pop    r14",
        "pop    r15",
        "pop    rbx",
        "pop    rsi",                                       // skip rdx, as it is a return value
        "pop    rsi",
        "pop    rdi",

        "pop    rbp",

        "pop    rcx",                                       // Pop userspace return pointer
        "pop    r11",                                       // pop rflags to r11

        "pop    QWORD PTR gs:{USR}",                        // Pop userspace rsp
        "mov    rsp, gs:{USR}",                             // Restore userspace rsp

        "swapgs",

        // swapgs variant of Spectre V1. Disable speculation past this point
        "lfence",
        "sysretq",

        ".popsection",

        USR = const USR_RSP_OFF,
        KRN = const KERNEL_RSP_OFF,

        syscall_rust = sym syscall_rust,
);

/// The syscall stack frame
#[derive(Debug)]
pub struct SyscallStackFrameValue {
    /// rax
    pub rax: u64,
    /// r8
    pub r8: u64,
    /// r9
    pub r9: u64,
    /// r10
    pub r10: u64,
    /// r12
    pub r12: u64,
    /// r13
    pub r13: u64,
    /// r14
    pub r14: u64,
    /// r15
    pub r15: u64,
    /// rbx
    pub rbx: u64,
    /// rdx
    pub rdx: u64,
    /// rsi
    pub rsi: u64,
    /// rdi
    pub rdi: u64,
    /// rbp
    pub rbp: u64,
    /// rcx
    pub rcx: u64,
    /// r11
    pub r11: u64,
    /// rsp
    pub rsp: u64,
}

/// Handle a syscall in rust
/// rdi, rsi, rdx, rcx, r8, r9
#[allow(clippy::many_single_char_names)]
extern "sysv64" fn syscall_rust(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    frame: *const SyscallStackFrameValue,
    nr: usize,
) -> X8664DoubleReturn {
    let orig_rdx: usize = c;
    let mut tcb = TcbRefCell::from_gs_base().borrow_mut();
    let mut h = HostCall::syscall(&mut tcb, frame);

    #[cfg(feature = "dbg")]
    if !(nr == SYS_write as usize && (a == STDERR_FILENO as usize || a == STDOUT_FILENO as usize)) {
        let tid = h.get_tid();
        eprintln!("[{tid}] syscall {nr} ...");
    }

    let usermemscope = UserMemScope;

    match nr as i64 {
        SYS_GETKEY => {
            let ret = h.get_key(&usermemscope, a, b);

            eprintln!(
                "syscall SYS_GETKEY = {}",
                ret.map_or_else(|e| -e as usize, |v| v)
            );

            match ret {
                Err(e) => {
                    X8664DoubleReturn {
                        rax: e.checked_neg().unwrap() as _,
                        // Preserve `rdx` as it is normally not clobbered with a syscall
                        rdx: orig_rdx as _,
                    }
                }
                Ok(rax) => {
                    X8664DoubleReturn {
                        rax: rax as _,
                        // Preserve `rdx` as it is normally not clobbered with a syscall
                        rdx: orig_rdx as _,
                    }
                }
            }
        }
        SYS_GETATT => {
            let ret = h.get_attestation(&usermemscope, a, b, c, d);

            #[cfg(feature = "dbg")]
            eprintln!(
                "syscall SYS_GETATT = {}",
                ret.map_or_else(|e| -e as usize, |v| v[0])
            );

            match ret {
                Err(e) => {
                    X8664DoubleReturn {
                        rax: e.checked_neg().unwrap() as _,
                        // Preserve `rdx` as it is normally not clobbered with a syscall
                        rdx: orig_rdx as _,
                    }
                }
                Ok([rax, rdx]) => X8664DoubleReturn {
                    rax: rax as _,
                    rdx: rdx as _,
                },
            }
        }
        SYS_exit => {
            let _ = h.exit(a as _);
            // Oddly, we need to manually drop here, although pickup_new_threads does not return
            drop(h);
            // Oddly, we need to manually drop here, although pickup_new_threads does not return
            drop(tcb);
            pickup_new_threads();
        }
        _ => {
            let ret = unsafe { h.syscall(&usermemscope, [nr, a, b, c, d, e, f]) };

            #[cfg(feature = "dbg")]
            if !(nr == SYS_write as usize
                && (a == STDERR_FILENO as usize || a == STDOUT_FILENO as usize))
            {
                eprintln!(
                    "syscall {} = {}",
                    nr,
                    ret.map_or_else(|e| -e as usize, |v| v[0])
                );
            }

            match ret {
                Err(e) => {
                    X8664DoubleReturn {
                        rax: e.checked_neg().unwrap() as _,
                        // Preserve `rdx` as it is normally not clobbered with a syscall
                        rdx: orig_rdx as _,
                    }
                }
                Ok([rax, _]) => {
                    X8664DoubleReturn {
                        rax: rax as _,
                        // Preserve `rdx` as it is normally not clobbered with a syscall
                        rdx: orig_rdx as _,
                    }
                }
            }
        }
    }
}
