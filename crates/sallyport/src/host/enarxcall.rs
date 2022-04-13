// SPDX-License-Identifier: Apache-2.0

use super::deref_aligned;
use crate::item::enarxcall::Number;
use crate::{item, Result};

use core::arch::asm;
use core::arch::x86_64::CpuidResult;

pub(super) unsafe fn execute(call: &mut item::Enarxcall, data: &mut [u8]) -> Result<()> {
    #[allow(clippy::single_match)]
    match call {
        item::Enarxcall {
            num: Number::Cpuid,
            argv: [leaf, sub_leaf, result_offset, ..],
            ret,
        } => {
            let result = deref_aligned::<CpuidResult>(data, *result_offset, 1)?;

            // Adapted from https://github.com/rust-lang/stdarch/blob/b4a0e07552cf90ef8f1a5b775bf70e4db94b3d63/crates/core_arch/src/x86/cpuid.rs#L51-L89

            // LLVM sometimes reserves `ebx` for its internal use, we so we need to use
            // a scratch register for it instead.
            #[cfg(target_arch = "x86_64")]
            asm!(
                "movq %rbx, {0:r}",
                "cpuid",
                "xchgq %rbx, {0:r}",
                lateout(reg) (*result).ebx,
                inlateout("eax") *leaf as u32 => (*result).eax,
                inlateout("ecx") *sub_leaf  as u32 => (*result).ecx,
                lateout("edx") (*result).edx,
                options(nostack, preserves_flags, att_syntax),
            );
            *ret = 0; // Indicate success
        }

        // Silently skip unsupported items
        _ => {}
    }
    Ok(())
}
