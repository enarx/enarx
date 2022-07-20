// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

musl_fsbase_fix!();

fn main() {
    let cpuid_result = unsafe { core::arch::x86_64::__cpuid_count(1, 0) };

    //assert that the CPU has an onboard x87 FPU
    assert!(cpuid_result.edx & (1 << 0) != 0);
}
