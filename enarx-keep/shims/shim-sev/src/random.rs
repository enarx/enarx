// SPDX-License-Identifier: Apache-2.0

//! Random functions

/// Get a random number
pub fn random() -> u64 {
    let mut r: u64 = 0;

    for _ in 0..1024 {
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut r) } == 1 {
            return r;
        }
    }

    panic!("Could not get random!")
}
