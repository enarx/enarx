// SPDX-License-Identifier: Apache-2.0

use bitflags::bitflags;

/// Various control flags modifying the basic operation of the CPU.
#[derive(Debug)]
pub struct XCr0;

bitflags! {
    /// Configuration flags of the XCr0 register XFEATURE_ENABLED_MASK.
    pub struct XCr0Flags: u64 {
        /// x87 FPU state management is supported by XSAVE/XRSTOR. Must be set to 1.
        #[allow(clippy::identity_op)]
        const X87 = 1 << 0;

        /// When set, 128-bit SSE state management is supported by
        /// XSAVE/XRSTOR. This bit must be set if YMM is set.
        /// Must be set to enable AVX extensions.
        const SSE = 1 << 1;

        /// When set, 256-bit SSE state management is supported by
        /// XSAVE/XRSTOR.
        /// Must be set to enable AVX extensions.
        const YMM = 1 << 2;
    }
}

extern "C" {
    fn _read_xcr0() -> u64;
    fn _write_xcr0(val: u64);
}

impl XCr0 {
    /// Read the current set of CR0 flags.
    pub fn read() -> XCr0Flags {
        XCr0Flags::from_bits_truncate(Self::read_raw())
    }

    /// Read the current raw CR0 value.
    #[inline(always)]
    pub fn read_raw() -> u64 {
        unsafe { _read_xcr0() }
    }

    /// Write XCR0 flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: XCr0Flags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(XCr0Flags::all().bits()) | XCr0Flags::X87.bits();
        let new_value = reserved | flags.bits() | {
            // if YMM is set, set SSE also
            if flags.contains(XCr0Flags::YMM) {
                XCr0Flags::SSE
            } else {
                XCr0Flags::empty()
            }
            .bits()
        };
        Self::write_raw(new_value);
    }

    /// Write raw XCR0 flags.
    ///
    /// Does _not_ preserve any values, including reserved fields. Unsafe because it's possible to
    /// set/unset required bits.
    #[inline(always)]
    pub unsafe fn write_raw(value: u64) {
        _write_xcr0(value)
    }

    /// Updates XCR0 flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn update<F>(f: F)
    where
        F: FnOnce(&mut XCr0Flags),
    {
        let mut flags = Self::read();
        f(&mut flags);
        Self::write(flags);
    }
}
