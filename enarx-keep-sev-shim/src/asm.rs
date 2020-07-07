// SPDX-License-Identifier: Apache-2.0

//! Declaration of extern assembler instructions
//!
//! Once stable rust has native asm!() this will go away

extern "C" {
    pub fn _enarx_asm_triple_fault() -> !;
    pub fn _rdfsbase() -> u64;
    pub fn _wrfsbase(val: u64);
}
