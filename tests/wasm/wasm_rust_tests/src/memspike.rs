// SPDX-License-Identifier: Apache-2.0

//! `memspike`'s primary intention is to trigger memory ballooning in
//! VM-based keeps. This will help test the ballooning itself as well
//! as memory pinning for SEV.

use std::collections::TryReserveError;

fn main() -> Result<(), TryReserveError> {
    let mut alloc: Vec<u8> = Vec::new();
    let _ = alloc.try_reserve(16_000_000)?;
    Ok(())
}
