// SPDX-License-Identifier: Apache-2.0

//! SSE related functions

use crate::interrupts::XSAVE_AREA_SIZE;
use crate::snp::cpuid_count;

use x86_64::registers::{
    mxcsr,
    mxcsr::MxCsr,
    xcontrol::{XCr0, XCr0Flags},
};

/// Setup and check SSE relevant stuff
#[cfg_attr(coverage, no_coverage)]
pub fn init_sse() {
    let cpuid_1_0 = cpuid_count(1, 0);

    const XSAVE_SUPPORTED_BIT: u32 = 1 << 26;
    let xsave_supported = (cpuid_1_0.ecx & XSAVE_SUPPORTED_BIT) != 0;
    assert!(xsave_supported);

    let mut xcr0 = XCr0::read();

    // check either SSE and SSE2 feature flags
    if cpuid_1_0.edx & 0x6000000 != 0 {
        xcr0 |= XCr0Flags::SSE;

        // check AVX feature flag
        if cpuid_1_0.ecx & 0x10000000 == 0x10000000 {
            xcr0 |= XCr0Flags::AVX;

            // check for AVX512F feature flag
            if cpuid_count(7, 0).ebx & 0x10000 == 0x10000 {
                xcr0 |= XCr0Flags::OPMASK | XCr0Flags::ZMM_HI256 | XCr0Flags::HI16_ZMM;
            }
        }

        unsafe { XCr0::write(xcr0) };
    }

    let xsave_size = cpuid_count(0xD, 0).ebx;

    // Make sure that interrupts have enough room for xsave
    assert!(xsave_size <= XSAVE_AREA_SIZE);
    mxcsr::write(
        MxCsr::INVALID_OPERATION_MASK
            | MxCsr::DENORMAL_MASK
            | MxCsr::DIVIDE_BY_ZERO_MASK
            | MxCsr::OVERFLOW_MASK
            | MxCsr::UNDERFLOW_MASK
            | MxCsr::PRECISION_MASK,
    );
}
