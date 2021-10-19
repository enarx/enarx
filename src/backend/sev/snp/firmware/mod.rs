// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::Firmware;

use super::Version;

use bitflags::bitflags;

use std::fmt::Debug;

/// The platform state.
///
/// The underlying SEV platform behaves like a state machine and can
/// only perform certain actions while it is in certain states.
#[derive(Copy, Clone, Debug, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum State {
    /// The platform is uninitialized.
    Uninitialized,

    /// The platform is initialized, but not currently managing any
    /// guests.
    Initialized,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            State::Uninitialized => "uninitialized",
            State::Initialized => "initialized",
        };
        write!(f, "{}", state)
    }
}

bitflags! {
    /// Describes the platform state.
    #[derive(Default)]
    pub struct Flags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

/// The CPU-unique identifier for the platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier(Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", b)?;
        }

        Ok(())
    }
}

/// Information regarding the SEV-SNP platform's TCB version.
#[derive(Clone, Debug, PartialEq)]
pub struct TcbStatus {
    /// Installed TCB version.
    pub platform_version: TcbVersion,

    /// Reported TCB version.
    pub reported_version: TcbVersion,
}

/// Information regarding the SEV-SNP platform's current status.
#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    /// The build information.
    pub build: Build,

    /// The platform's current state.
    pub state: State,

    /// Set, if the Reverse Map Table (RMP) is initialized
    pub is_rmp_init: bool,

    /// If set, the identifier, unique to the chip, is masked out
    /// in the attestation report
    pub mask_chip_id: bool,

    /// The number of valid guests supervised by this platform.
    pub guests: u32,

    /// TCB status.
    pub tcb: TcbStatus,
}

/// A description of the SEV-SNP platform's build information.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Build {
    /// The version information.
    pub version: Version,

    /// The build ID.
    pub build: u32,
}

impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.version, self.build)
    }
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct TcbVersion {
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    _reserved: [u8; 4],
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}
