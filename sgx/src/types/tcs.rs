// SPDX-License-Identifier: Apache-2.0

//! Thread Control Structure (Section 38.8)
//! Each executing thread in the enclave is associated with a Thread Control Structure.

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
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Tcs {
    /// Used to mark an entered TCS.
    state: u64,
    /// Execution flags (cleared by EADD)
    flags: Flags,
    /// SSA stack offset relative to the enclave base
    ossa: u64,
    /// The current SSA frame index (cleared by EADD)
    cssa: u32,
    /// The number of frames in the SSA stack
    nssa: u32,
    /// Entry point offset relative to the enclave base.
    oentry: u64,
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
}

impl Tcs {
    /// Creates new TCS from an entry offset, SSA offset, and number of SSA frames.
    pub fn new(entry: usize, ssa: usize, nssa: u32) -> Self {
        Self {
            state: 0,
            flags: Flags::empty(),
            ossa: ssa as _,
            cssa: 0,
            nssa,
            oentry: entry as _,
            aep: 0,
            ofsbasgx: 0,
            ogsbasgx: 0,
            fslimit: !0,
            gslimit: !0,
        }
    }
}

#[cfg(test)]
testaso! {
    struct Tcs: 8, 72 => {
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
        gslimit: 68
    }
}
