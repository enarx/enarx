// SPDX-License-Identifier: Apache-2.0

use crate::Version;

/// Reset the platform's persistent state.
///
/// (Chapter 5.5)
pub struct PlatformReset;

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct PlatformStatusFlags: u8 {
    /// If set, the platform is externally owned.
    /// Else, it is self-owned (default state).
        const OWNER = 1;
    }
}

bitfield::bitfield! {
    /// Contains information that describes how the
    /// platform is currently configured.
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    pub struct PlatformStatusConfig(u32);
    impl Debug;

    /// If set, SEV-ES is initialized for the platform.
    pub encrypted_state, _: 0, 0;
    reserved, _: 23, 1;

    /// The firmware build ID for this API version.
    pub build, _: 31, 24;
}

/// Query SEV platform status.
///
/// (Chapter 5.6; Table 17)
#[derive(Default)]
#[repr(C, packed)]
pub struct PlatformStatus {
    /// The firmware version (major.minor)
    pub version: Version,

    /// The Platform State.
    pub state: u8,

    /// Right now the only flag that is communicated in
    /// this single byte is whether the platform is self-
    /// owned or not. If the first bit is set then the
    /// platform is externally owned. If it is cleared, then
    /// the platform is self-owned. Self-owned is the default
    /// state.
    pub flags: PlatformStatusFlags,

    /// Contains configuration information about the platform.
    pub config: PlatformStatusConfig,

    /// The number of valid guests maintained by the SEV firmware.
    pub guest_count: u32,
}
