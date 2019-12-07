bitflags::bitflags! {
    /// Section 38.8.1
    pub struct Flags: u64 {
        const DBGOPTIN = 1 << 0;
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags::empty()
    }
}

/// Thread Control Structure (TCS) is an enclave page visible in its address
/// space that defines an entry point inside the enclave. A thread enters inside
/// an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
/// by only one thread at a time.
///
/// Section 38.8
#[derive(Debug, Default)]
#[repr(C, align(4096))]
pub struct Tcs {
    state: u64,         // used to mark an entered TCS
    flags: Flags,       // execution flags (cleared by EADD)
    ssa_offset: u64,    // SSA stack offset relative to the enclave base
    ssa_index: u32,     // the current SSA frame index (cleard by EADD)
    nr_ssa_frames: u32, // the number of frames in the SSA stack
    entry_offset: u64,  // entry point offset relative to the enclave base
    exit_addr: u64,     // address outside enclave to exit on an exception or interrupt
    fs_offset: u64,     // offset relative to enclave base to become FS segment inside the enclave
    gs_offset: u64,     // offset relative to enclave base to become GS segment inside the enclave
    fs_limit: u32,      // size to become a new FS-limit (only 32-bit enclaves)
    gs_limit: u32,      // size to become a new GS-limit (only 32-bit enclaves)
}

testaso! {
    struct Tcs: 4096, 4096 => {
        state: 0,
        flags: 8,
        ssa_offset: 16,
        ssa_index: 24,
        nr_ssa_frames: 28,
        entry_offset: 32,
        exit_addr: 40,
        fs_offset: 48,
        gs_offset: 56,
        fs_limit: 64,
        gs_limit: 68
    }
}
