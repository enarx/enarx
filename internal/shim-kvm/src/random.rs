// SPDX-License-Identifier: Apache-2.0

//! Random functions

use crate::snp::{cpuid, snp_active};

use spinning::Lazy;

/// Flag, if the CPU supports RDRAND
pub static CPU_HAS_RDRAND: Lazy<bool> = Lazy::new(|| cpuid(1).ecx & (1 << 30) != 0);

/// Get a random number
pub fn random() -> u64 {
    let mut r: u64 = 0;

    if *CPU_HAS_RDRAND {
        for _ in 0..1024 {
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut r) } == 1 {
                return r;
            }
        }
    } else {
        // This is an absolute fallback for old CPUs to be able to run in KVM simulation mode

        if snp_active() {
            panic!("No rdrand on SNP");
        }

        return unsafe { core::arch::x86_64::_rdtsc() };
    }

    panic!("Could not get random!")
}
