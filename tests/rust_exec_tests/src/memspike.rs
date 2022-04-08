// SPDX-License-Identifier: Apache-2.0

//! `memspike`'s primary intention is to trigger memory ballooning in
//! VM-based keeps. This will help test the ballooning itself as well
//! as memory pinning for SEV.

#![feature(core_ffi_c)]

use rust_exec_tests::musl_fsbase_fix;
use std::collections::TryReserveError;

musl_fsbase_fix!();

fn main() -> Result<(), TryReserveError> {
    let mut alloc: Vec<u8> = Vec::new();
    let _ = alloc.try_reserve(40_000_000)?;
    Ok(())
}
