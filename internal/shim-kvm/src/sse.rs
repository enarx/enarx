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
pub fn init_sse() {
    const XSAVE_SUPPORTED_BIT: u32 = 1 << 26;
    let xsave_supported = (cpuid_count(1, 0).ecx & XSAVE_SUPPORTED_BIT) != 0;
    assert!(xsave_supported);

    let xsaveopt_supported = (cpuid_count(0xD, 1).eax & 1) == 1;
    assert!(xsaveopt_supported);

    let sse_extended_supported = (cpuid_count(0xd, 0).eax & 0b111) == 0b111;

    if sse_extended_supported {
        let mut xcr0 = XCr0::read();
        xcr0 |= XCr0Flags::AVX | XCr0Flags::SSE;
        unsafe { XCr0::write(xcr0) };
    } else {
        let mut xcr0 = XCr0::read();
        xcr0 |= XCr0Flags::SSE;
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
