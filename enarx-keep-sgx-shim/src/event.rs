// SPDX-License-Identifier: Apache-2.0

use intel_types::Exception;
use nolibc::x86_64::error::Number as ErrNo;
use nolibc::x86_64::syscall::Number as SysCall;
use sgx_types::ssa::StateSaveArea;

use crate::handler::{Context, Handler, Print};
use crate::Layout;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: &[u8] = &[0x0f, 0x05];
const OP_CPUID: &[u8] = &[0x0f, 0xa2];

#[no_mangle]
pub extern "C" fn event(
    _rdi: u64,
    _rsi: u64,
    _rdx: u64,
    layout: &Layout,
    _r8: u64,
    _r9: u64,
    aex: &mut StateSaveArea,
    ctx: &Context,
) {
    let mut h = Handler::new(layout, aex, ctx);

    // Exception Vector Table
    match h.aex.gpr.exitinfo.exception() {
        Some(Exception::InvalidOpcode) => {
            match unsafe { core::slice::from_raw_parts(h.aex.gpr.rip as *const u8, 2) } {
                OP_SYSCALL => {
                    aex.gpr.rax = match h.aex.gpr.rax.into() {
                        SysCall::READ => h.read(),
                        SysCall::READV => h.readv(),
                        SysCall::WRITE => h.write(),
                        SysCall::WRITEV => h.writev(),
                        SysCall::EXIT => h.exit(None),
                        SysCall::GETUID => h.getuid(),
                        SysCall::ARCH_PRCTL => h.arch_prctl(),
                        SysCall::EXIT_GROUP => h.exit_group(None),
                        SysCall::SET_TID_ADDRESS => h.set_tid_address(),
                        SysCall::BRK => h.brk(),
                        SysCall::UNAME => h.uname(),
                        SysCall::MPROTECT => h.mprotect(),
                        SysCall::MMAP => h.mmap(),
                        SysCall::MUNMAP => h.munmap(),
                        SysCall::RT_SIGACTION => h.rt_sigaction(),
                        SysCall::RT_SIGPROCMASK => h.rt_sigprocmask(),
                        SysCall::SIGALTSTACK => h.sigaltstack(),

                        syscall => {
                            h.print("unsupported syscall: ");
                            h.print(&syscall);
                            h.print("\n");
                            ErrNo::ENOSYS.into_syscall()
                        }
                    };

                    aex.gpr.rip += 2;
                }

                OP_CPUID => {
                    let (rax, rbx, rcx, rdx) = match (h.aex.gpr.rax, h.aex.gpr.rcx) {
                        (0, _) => (0, 0x756e_6547, 0x6c65_746e, 0x4965_6e69), // "GenuineIntel"

                        (a, c) => {
                            h.print("unsupported cpuid: (");
                            h.print(&a);
                            h.print(", ");
                            h.print(&c);
                            h.print(")\n");

                            (0, 0, 0, 0)
                        }
                    };

                    aex.gpr.rax = rax;
                    aex.gpr.rbx = rbx;
                    aex.gpr.rcx = rcx;
                    aex.gpr.rdx = rdx;
                    aex.gpr.rip += 2;
                }

                // unsupported opcode
                r => {
                    let opcode = (r[0] as u16) << 8 | r[1] as u16;
                    h.print("unsupported opcode: ");
                    h.print(&opcode);
                    h.print("\n");
                    h.exit(1)
                }
            }
        }

        // Not InvalidOpcode
        _ => {
            h.attacked();
        }
    }
}
