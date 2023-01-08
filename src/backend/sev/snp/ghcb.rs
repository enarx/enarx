// SPDX-License-Identifier: Apache-2.0

// TODO: Consider sharing these types with the shim.

use const_default::ConstDefault;

/// GHCB Save Area
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, packed)]
pub struct GhcbSaveArea {
    reserved1: [u8; 203],
    pub cpl: u8,
    reserved8: [u8; 300],
    pub rax: u64,
    reserved4: [u8; 264],
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    reserved5: [u8; 112],
    pub sw_exit_code: u64,
    pub sw_exit_info1: u64,
    pub sw_exit_info2: u64,
    pub sw_scratch: u64,
    reserved6: [u8; 56],
    pub xcr0: u64,
    pub valid_bitmap: [u8; 16],
    pub x87state_gpa: u64,
    reserved7: [u8; 1016],
}

/// GHCB
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, align(4096))]
pub struct Ghcb {
    pub save_area: GhcbSaveArea,
    pub shared_buffer: [u8; 2032],
    reserved1: [u8; 10],
    pub protocol_version: u16,
    pub ghcb_usage: u32,
}

/// GHCB page state description
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C)]
pub struct SnpPscDesc {
    pub cur_entry: u16,
    pub end_entry: u16,
    pub reserved: u32,
    pub entries: [PscEntry; 253],
}

/// GHCB page state entry
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C)]
pub struct PscEntry {
    pub entry: u64,
}
