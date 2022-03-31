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

impl Identifier {
    // Get a unique identifier for the VCEK key to be used in linux file names
    pub fn vcek_cache_name(&self, version: &TcbVersion) -> String {
        format!(
            "vcek-{:x}-{:02}-{:02}-{:02}-{:02}",
            self, version.bootloader, version.tee, version.snp, version.microcode,
        )
    }

    /// Get the URL to download the VCEK.
    pub fn vcek_url(&self, version: &TcbVersion) -> String {
        format!(
            "https://kdsintf.amd.com/vcek/v1/Milan/{:x}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            self,
            version.bootloader,
            version.tee,
            version.snp,
            version.microcode,
        )
    }
}

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl From<Vec<u8>> for Identifier {
    fn from(vec: Vec<u8>) -> Self {
        Identifier(vec)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", b)?;
        }

        Ok(())
    }
}

impl std::fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02x}", b)?;
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    pub _reserved: [u8; 4],
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vcek_url() {
        const URL: &str = "https://kdsintf.amd.com/vcek/v1/Milan/8ba826b2dd6ab65e401e0c4d4128ef4b434ed0ccb213f66c5f577b518730ef5892f78a78be259976973125a3b9b3d19f286c912cf5776fdfcee5260fa4576c4b?blSPL=00&teeSPL=00&snpSPL=03&ucodeSPL=29";

        let id = Identifier(vec![
            0x8b, 0xa8, 0x26, 0xb2, 0xdd, 0x6a, 0xb6, 0x5e, 0x40, 0x1e, 0x0c, 0x4d, 0x41, 0x28,
            0xef, 0x4b, 0x43, 0x4e, 0xd0, 0xcc, 0xb2, 0x13, 0xf6, 0x6c, 0x5f, 0x57, 0x7b, 0x51,
            0x87, 0x30, 0xef, 0x58, 0x92, 0xf7, 0x8a, 0x78, 0xbe, 0x25, 0x99, 0x76, 0x97, 0x31,
            0x25, 0xa3, 0xb9, 0xb3, 0xd1, 0x9f, 0x28, 0x6c, 0x91, 0x2c, 0xf5, 0x77, 0x6f, 0xdf,
            0xce, 0xe5, 0x26, 0x0f, 0xa4, 0x57, 0x6c, 0x4b,
        ]);

        let tcb = TcbVersion {
            bootloader: 0,
            tee: 0,
            snp: 3,
            microcode: 29,
            ..Default::default()
        };

        assert_eq!(URL, id.vcek_url(&tcb));
    }
}
