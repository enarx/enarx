// SPDX-License-Identifier: Apache-2.0

use sallyport::Block;
use sgx::types::ssa::{Exception, StateSaveArea};

use crate::handler::{Context, Handler};
use crate::Layout;
use syscall::SyscallHandler;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: &[u8] = &[0x0f, 0x05];
const OP_CPUID: &[u8] = &[0x0f, 0xa2];
const SYS_ERESUME: usize = !0;

#[no_mangle]
pub extern "C" fn event(
    _rdi: u64,
    _rsi: u64,
    block: &mut Block,
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
            match unsafe { h.aex.gpr.rip.into_slice(2usize) } {
                OP_SYSCALL => {
                    let ret = h.syscall(
                        h.aex.gpr.rdi.into(),
                        h.aex.gpr.rsi.into(),
                        h.aex.gpr.rdx.into(),
                        h.aex.gpr.r10.into(),
                        h.aex.gpr.r8.into(),
                        h.aex.gpr.r9.into(),
                        h.aex.gpr.rax.into(),
                    );

                    aex.gpr.rip = (usize::from(aex.gpr.rip) + 2).into();
                    match ret {
                        Err(e) => aex.gpr.rax = (-e).into(),
                        Ok([rax, rdx]) => {
                            aex.gpr.rax = rax.into();
                            aex.gpr.rdx = rdx.into();
                        }
                    }
                }

                OP_CPUID => {
                    h.cpuid();
                    aex.gpr.rip = (usize::from(aex.gpr.rip) + 2).into();
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

    block.msg.req.num = SYS_ERESUME.into();
}
