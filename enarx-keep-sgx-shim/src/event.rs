// SPDX-License-Identifier: Apache-2.0

use core::convert::TryInto;
use intel_types::Exception;
use memory::Register;
use sallyport::Block;
use sgx_types::ssa::StateSaveArea;

use crate::handler::{Context, Handler};
use crate::Layout;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: &[u8] = &[0x0f, 0x05];
const OP_CPUID: &[u8] = &[0x0f, 0xa2];

#[no_mangle]
pub extern "C" fn event(
    block: &mut Block,
    _rsi: u64,
    _rdx: u64,
    layout: &Layout,
    _r8: u64,
    _r9: u64,
    aex: &mut StateSaveArea,
    ctx: &Context,
) {
    let mut h = Handler::new(layout, aex, ctx, block);

    // Exception Vector Table
    match h.aex.gpr.exitinfo.exception() {
        Some(Exception::InvalidOpcode) => {
            match unsafe { core::slice::from_raw_parts(h.aex.gpr.rip.raw() as *const u8, 2) } {
                OP_SYSCALL => {
                    aex.gpr.rax = Register::from_raw(
                        match h
                            .aex
                            .gpr
                            .rax
                            .raw()
                            .try_into()
                            .unwrap_or(h.aex.gpr.rax.raw() as i64)
                        {
                            libc::SYS_read => h.read(),
                            libc::SYS_readv => h.readv(),
                            libc::SYS_write => h.write(),
                            libc::SYS_writev => h.writev(),
                            libc::SYS_exit => h.exit(None),
                            libc::SYS_getuid => h.getuid(),
                            libc::SYS_arch_prctl => h.arch_prctl(),
                            libc::SYS_exit_group => h.exit_group(None),
                            libc::SYS_set_tid_address => h.set_tid_address(),
                            libc::SYS_brk => h.brk(),
                            libc::SYS_uname => h.uname(),
                            libc::SYS_mprotect => h.mprotect(),
                            libc::SYS_mmap => h.mmap(),
                            libc::SYS_munmap => h.munmap(),
                            libc::SYS_rt_sigaction => h.rt_sigaction(),
                            libc::SYS_rt_sigprocmask => h.rt_sigprocmask(),
                            libc::SYS_sigaltstack => h.sigaltstack(),
                            libc::SYS_getrandom => h.getrandom(),

                            syscall => {
                                debugln!(h, "unsupported syscall: 0x{:x}", syscall as u64);
                                -libc::ENOSYS as u64
                            }
                        },
                    );

                    aex.gpr.rip = Register::from_raw(aex.gpr.rip.raw() + 2);
                }

                OP_CPUID => {
                    let (rax, rbx, rcx, rdx) = match (h.aex.gpr.rax.raw(), h.aex.gpr.rcx.raw()) {
                        (0, _) => (0, 0x756e_6547, 0x6c65_746e, 0x4965_6e69), // "GenuineIntel"
                        (a, c) => {
                            debugln!(h, "unsupported cpuid: (0x{:x}, 0x{:x})", a, c);
                            (0, 0, 0, 0)
                        }
                    };

                    aex.gpr.rax = Register::from_raw(rax);
                    aex.gpr.rbx = Register::from_raw(rbx);
                    aex.gpr.rcx = Register::from_raw(rcx);
                    aex.gpr.rdx = Register::from_raw(rdx);
                    aex.gpr.rip = Register::from_raw(aex.gpr.rip.raw() + 2);
                }

                // unsupported opcode
                r => {
                    debugln!(h, "unsupported opcode: {:?}", r);
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
