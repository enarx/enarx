// SPDX-License-Identifier: Apache-2.0

use nolibc::x86_64::syscall::Number as SysCall;
use sgx_types::ssa::StateSaveArea;

use crate::handler::{Context, Handler};
use crate::Layout;

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
    match unsafe { core::slice::from_raw_parts(aex.gpr.rip as *const u8, 2) } {
        // syscall
        [0x0f, 0x05] => {
            let syscall = aex.gpr.rax.into();
            let mut h = Handler::new(layout, aex, ctx);

            aex.gpr.rax = match syscall {
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
                _ => h.exit(254),
            };

            aex.gpr.rip += 2;
        }

        _ => Handler::new(layout, aex, ctx).exit(255),
    };
}
