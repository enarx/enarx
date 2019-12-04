const SGX_TCS_RESERVED_SIZE: usize = 4024;

/// Thread Control Structure (TCS) is an enclave page visible in its address
/// space that defines an entry point inside the enclave. A thread enters inside
/// an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
/// by only one thread at a time.
#[repr(C, align(4096))]
pub struct Tcs {
    state: u64,         // used to mark an entered TCS
    flags: u64,         // execution flags (cleared by EADD)
    ssa_offset: u64,    // SSA stack offset relative to the enclave base
    ssa_index: u32,     // the current SSA frame index (cleard by EADD)
    nr_ssa_frames: u32, // the number of frames in the SSA stack
    entry_offset: u64,  // entry point offset relative to the enclave base
    exit_addr: u64,     // address outside enclave to exit on an exception or interrupt
    fs_offset: u64,     // offset relative to enclave base to become FS segment inside the enclave
    gs_offset: u64,     // offset relative to enclave base to become GS segment inside the enclave
    fs_limit: u32,      // size to become a new FS-limit (only 32-bit enclaves)
    gs_limit: u32,      // size to become a new GS-limit (only 32-bit enclaves)
    reserved: [u8; SGX_TCS_RESERVED_SIZE],
}

impl Default for Tcs {
    fn default() -> Self {
        Tcs {
            state: u64::default(),
            flags: u64::default(),
            ssa_offset: u64::default(),
            ssa_index: u32::default(),
            nr_ssa_frames: u32::default(),
            entry_offset: u64::default(),
            exit_addr: u64::default(),
            fs_offset: u64::default(),
            gs_offset: u64::default(),
            fs_limit: u32::default(),
            gs_limit: u32::default(),
            reserved: [0u8; SGX_TCS_RESERVED_SIZE],
        }
    }
}
