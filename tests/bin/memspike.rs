// SPDX-License-Identifier: Apache-2.0

//! `memspike`'s primary intention is to trigger memory ballooning in
//! VM-based keeps. This will help test the ballooning itself as well
//! as memory pinning for SEV.

fn main() {
    let _alloc: Vec<u8> = Vec::with_capacity(40_000_000);
}
