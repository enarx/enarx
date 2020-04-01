// SPDX-License-Identifier: Apache-2.0

use nolibc::x86_64::syscall::Number as SysCall;
use sgx_types::{ssa::StateSaveArea, tcs::Tcs};

use crate::handler::{Context, Handler};

#[no_mangle]
pub extern "C" fn event(
    _rdi: u64,
    _rsi: u64,
    _rdx: u64,
    tcs: &Tcs,
    _r8: u64,
    _r9: u64,
    aex: &mut StateSaveArea,
    ctx: &Context,
) {
    match unsafe { core::slice::from_raw_parts(aex.gpr.rip as *const u8, 2) } {
        // syscall
        [0x0f, 0x05] => {
            let syscall = aex.gpr.rax.into();
            let mut h = Handler::new(tcs, aex, ctx);

            aex.gpr.rax = match syscall {
                SysCall::READ => h.read(),
                SysCall::WRITE => h.write(),
                SysCall::GETUID => h.getuid(),
                SysCall::EXIT => h.exit(None),
                SysCall::EXIT_GROUP => h.exit_group(None),
                SysCall::SET_TID_ADDRESS => h.set_tid_address(),
                _ => h.exit(254),
            };

            aex.gpr.rip += 2;
        }

        _ => Handler::new(tcs, aex, ctx).exit(255),
    };
}
