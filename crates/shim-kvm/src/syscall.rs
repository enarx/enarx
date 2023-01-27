// SPDX-License-Identifier: Apache-2.0

//! syscall interface layer between assembler and rust

use crate::hostcall::{HostCall, UserMemScope};
use crate::spin::{Locked, RacyCell};

use core::arch::global_asm;
use core::mem::size_of;

use sallyport::guest;
use sallyport::guest::Handler;
use sallyport::item::enarxcall::{SYS_GETATT, SYS_GETKEY};
#[cfg(feature = "dbg")]
use sallyport::libc::{SYS_write, STDERR_FILENO, STDOUT_FILENO};
use spin::Lazy;

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
// TaskStateSegment.privilege_stack_table[0]
const KERNEL_RSP_OFF: usize = size_of::<u32>();
// TaskStateSegment.privilege_stack_table[3]
const USR_RSP_OFF: usize = size_of::<u32>() + 3 * size_of::<u64>();
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
        "mov    QWORD PTR gs:{USR},     0x0",               // clear userspace rsp in the TSS
        "push   r11",                                       // push RFLAGS stored in r11
        "push   rcx",                                       // push userspace return pointer
        "push   rbp",
        "mov    rbp,                    rsp",               // Save stack frame

        // Arguments in registers:
        // SYSV:    rdi, rsi, rdx, rcx, r8, r9
        // SYSCALL: rdi, rsi, rdx, r10, r8, r9 and syscall number in rax
        "mov    rcx,                    r10",

        // These will be preserved by `syscall_rust` via the SYS-V ABI
        // rbx, rsp, rbp, r12, r13, r14, r15

        // save registers
        "push   rdi",
        "push   rsi",
        "push   r10",
        "push   r9",
        "push   r8",

        // syscall number on the stack as the seventh argument
        "push   rax",

        "call   {syscall_rust}",

        // skip rax pop, as it is the return value
        "add    rsp,                    0x8",

        // restore registers
        "pop    r8",
        "pop    r9",
        "pop    r10",
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

/// Thread local storage
/// FIXME: when using multithreading
pub static THREAD_TLS: Lazy<Locked<&mut guest::ThreadLocalStorage>> = Lazy::new(|| unsafe {
    static TLSHANDLE: RacyCell<guest::ThreadLocalStorage> =
        RacyCell::new(guest::ThreadLocalStorage::new());
    Locked::<&mut guest::ThreadLocalStorage>::new(&mut (*TLSHANDLE.get()))
});

/// Handle a syscall in rust
#[allow(clippy::many_single_char_names)]
extern "sysv64" fn syscall_rust(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    nr: usize,
) -> X8664DoubleReturn {
    let orig_rdx: usize = c;

    #[cfg(feature = "dbg")]
    if !(nr == SYS_write as usize && (a == STDERR_FILENO as usize || a == STDOUT_FILENO as usize)) {
        eprintln!("syscall {nr} ...")
    }

    let mut tls = THREAD_TLS.lock();
    let mut h = HostCall::try_new(&mut tls).unwrap();

    let usermemscope = UserMemScope;

    match nr as i64 {
        SYS_GETKEY => {
            let ret = h.get_key(&usermemscope, a, b);

            #[cfg(feature = "dbg")]
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
