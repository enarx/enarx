// SPDX-License-Identifier: Apache-2.0

//! Thread Control Structure (Section 38.8)
//! Each executing thread in the enclave is associated with a Thread Control Structure.

use addr::Offset;
#[cfg(test)]
use testing::testaso;

bitflags::bitflags! {
    /// Section 38.8.1
    #[derive(Default)]
    #[repr(transparent)]
    pub struct Flags: u64 {
        /// Allows debugging features while executing in the enclave on this TCS. Hardware clears this bit on EADD.
        const DBGOPTIN = 1 << 0;
    }
}

/// Thread Control Structure (TCS) is an enclave page visible in its address
/// space that defines an entry point inside the enclave. A thread enters inside
/// an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
/// by only one thread at a time.
///
/// Section 38.8
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct Tcs {
    /// Used to mark an entered TCS.
    state: u64,
    /// Execution flags (cleared by EADD)
    flags: Flags,
    /// SSA stack offset relative to the enclave base
    ossa: Offset<u64>,
    /// The current SSA frame index (cleared by EADD)
    cssa: u32,
    /// The number of frames in the SSA stack
    nssa: u32,
    /// Entry point offset relative to the enclave base.
    oentry: Offset<u64>,
    /// Address outside enclave to exit on an exception or interrupt.
    aep: u64,
    /// Offset relative to enclave base to become FS segment inside the enclave.
    ofsbasgx: u64,
    /// Offset relative to enclave base to become GS segment inside the enclave.
    ogsbasgx: u64,
    /// Size to become a new FS-limit (only 32-bit enclaves).
    fslimit: u32,
    /// Size to become a new GS-limit (only 32-bit enclaves).
    gslimit: u32,
    reserved0: [u64; 23],
    reserved1: [[u64; 32]; 15],
}

impl Tcs {
    /// Creates new TCS from an entry offset, SSA offset, and number of SSA frames.
    pub fn new(entry: Offset<usize>, ssa: Offset<usize>, nssa: u32) -> Self {
        Self {
            state: 0,
            flags: Flags::empty(),
            ossa: ssa.into(),
            cssa: 0,
            nssa,
            oentry: entry.into(),
            aep: 0,
            ofsbasgx: 0,
            ogsbasgx: 0,
            fslimit: !0,
            gslimit: !0,
            reserved0: [0; 23],
            reserved1: [[0; 32]; 15],
        }
    }
}

impl AsRef<[u8]> for Tcs {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

#[cfg(test)]
testaso! {
    struct Tcs: 4096, 4096 => {
        state: 0,
        flags: 8,
        ossa: 16,
        cssa: 24,
        nssa: 28,
        oentry: 32,
        aep: 40,
        ofsbasgx: 48,
        ogsbasgx: 56,
        fslimit: 64,
        gslimit: 68,
        reserved0: 72,
        reserved1: 256
    }
}
