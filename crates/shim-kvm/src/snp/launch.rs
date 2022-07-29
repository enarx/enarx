// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP launch process parameters
#![allow(clippy::integer_arithmetic)]

use bitflags::bitflags;

/// Information about the SEV platform version.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor: u8,
}

bitflags! {
    /// Configurable SNP Policy options.
    #[derive(Default)]
    pub struct PolicyFlags: u16 {
        /// Enable if SMT is enabled in the host machine.
        const SMT = 1;

        /// If enabled, association with a migration agent is allowed.
        const MIGRATE_MA = 1 << 2;

        /// If enabled, debugging is allowed.
        const DEBUG = 1 << 3;

        /// Enable if SMT is enabled in the host machine.
        const SINGLE_SOCKET = 1 << 4;
    }
}

/// Describes a policy that the AMD Secure Processor will
/// enforce.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The various policy optons are encoded as bit flags.
    pub flags: PolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

impl Policy {
    /// turn the policy into a u64
    pub const fn as_u64(&self) -> u64 {
        let mut val: u64 = 0;

        let minor_version = self.minfw.minor as u64;
        let mut major_version = self.minfw.major as u64;

        /*
         * According to the SNP firmware spec, bit 1 of the policy flags is reserved and must
         * always be set to 1. Rather than passing this responsibility off to callers, set this bit
         * every time an ioctl is issued to the kernel.
         */
        let flags = self.flags.bits() | 0b10;
        let mut flags_64 = flags as u64;

        major_version <<= 8;
        flags_64 <<= 16;

        val |= minor_version;
        val |= major_version;
        val |= flags_64;
        // mask out all the other invalid bits per SEV-SNP firmware specification
        val &= 0x00FFFFFF;

        val
    }
}

impl From<Policy> for u64 {
    fn from(policy: Policy) -> u64 {
        policy.as_u64()
    }
}
