// Copyright 2020 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Thread Control Structure (Section 38.8)
//! Each executing thread in the enclave is associated with a Thread Control Structure.

bitflags::bitflags! {
    /// Section 38.8.1
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
    ssa_offset: u64,
    /// The current SSA frame index (cleared by EADD)
    ssa_index: u32,
    /// The number of frames in the SSA stack
    nr_ssa_frames: u32,
    /// Entry point offset relative to the enclave base.
    entry_offset: u64,
    /// Address outside enclave to exit on an exception or interrupt.
    exit_addr: u64,
    /// Offset relative to enclave base to become FS segment inside the enclave.
    fs_offset: u64,
    /// Offset relative to enclave base to become GS segment inside the enclave.
    gs_offset: u64,
    /// Size to become a new FS-limit (only 32-bit enclaves).
    fs_limit: u32,
    /// Size to become a new GS-limit (only 32-bit enclaves).
    gs_limit: u32,
}

impl Tcs {
    /// Creates new TCS from an entry offset, SSA offset, and number of SSA frames.
    pub const fn new(entry: u64, ssa: u64, nssa: u32) -> Self {
        Self {
            state: 0,
            flags: Flags::empty(),
            ssa_offset: ssa,
            ssa_index: 0,
            nr_ssa_frames: nssa,
            entry_offset: entry,
            exit_addr: 0,
            fs_offset: 0,
            gs_offset: 0,
            fs_limit: 0,
            gs_limit: 0,
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
