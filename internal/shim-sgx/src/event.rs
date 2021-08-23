// SPDX-License-Identifier: Apache-2.0

use sallyport::Block;
use sgx::types::ssa::{Exception, StateSaveArea};

use crate::handler::Handler;
use crate::Layout;
use sallyport::syscall::{BaseSyscallHandler, ProcessSyscallHandler, SyscallHandler};

pub fn event(layout: &Layout, aex: &mut StateSaveArea, block: &mut Block) {
    let mut h = Handler::new(layout, aex, block);

    // Exception Vector Table
    match h.aex.gpr.exitinfo.exception() {
        Some(Exception::InvalidOpcode) => {
            match unsafe { h.aex.gpr.rip.into_slice(2usize) } {
                super::OP_SYSCALL => {
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

                super::OP_CPUID => {
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
}
