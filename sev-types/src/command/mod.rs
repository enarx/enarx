// SPDX-License-Identifier: Apache-2.0

//! The `command` module contains a number of types that are
//! useful for interacting in a low-level SEV environment.

use core::marker::PhantomData;

use bitfield::bitfield;
use bitflags::bitflags;

use crate::platform::Version;

/// Reset SEV persistent state.
///
/// (Chapter 5.5)
#[repr(C, packed)]
pub struct PlatformReset;

// FIXME: https://github.com/rust-lang/rustfmt/issues/4085
#[rustfmt::skip]
bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct PlatformStatusFlags: u8 {
	/// If set, the platform is externally owned.
	/// Else, it is self-owned (default state).
        const OWNER = 1;
    }
}

bitfield! {
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

/// Generate a new Platform Encryption Key (PEK).
///
/// (Chapter 5.7)
#[repr(C, packed)]
pub struct PekGenerate;

/// Take ownership of the platform.
///
/// (Chapter 5.8)
#[repr(C, packed)]
pub struct PekCertificateSigningRequest<'a> {
    /// The system's physical address of a memory region that
    /// the platform will write the PEK certificate to.
    addr: u64,

    /// The length of the memory region (in bytes) that will contain
    /// the PEK certificate.
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PekCertificateSigningRequest<'a> {
    #![allow(missing_docs)]
    pub fn new(addr: u64, len: u32) -> Self {
        Self {
            addr,
            len,
            _phantom: PhantomData,
        }
    }
}

/// Import the PEK and the OCA into the platform.
///
/// (Chapter 5.9; Table 22)
#[repr(C, packed)]
pub struct PekCertificateImport<'a> {
    /// The system physical address of the memory region
    /// that contains the PEK certificate.
    pek_addr: u64,

    /// The length of the memory region (in bytes) that
    /// contains the PEK certificate.
    pek_size: u32,

    /// The system physical address of the memory region
    /// that contains the OCA certificate.
    oca_addr: u64,

    /// The length of the memory region (in bytes) that contains
    /// the OCA certificate.
    oca_size: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PekCertificateImport<'a> {
    #![allow(missing_docs)]
    pub fn new(pek_addr: u64, pek_size: u32, oca_addr: u64, oca_size: u32) -> Self {
        Self {
            pek_addr,
            pek_size,
            oca_addr,
            oca_size,
            _phantom: PhantomData,
        }
    }
}

/// (Re)generate the Platform Diffie-Hellman (PDH).
///
/// (Chapter 5.10)
#[repr(C, packed)]
pub struct PdhGenerate;

/// Retrieve the PDH and the certificate chain that testifies
/// to the identity of the platform.
///
/// (Chapter 5.11; Table 25)
#[repr(C, packed)]
pub struct PdhCertificateExport<'a> {
    pdh_addr: u64,
    pdh_size: u32,
    chain_addr: u64,
    chain_size: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PdhCertificateExport<'a> {
    #![allow(missing_docs)]
    pub fn new(pdh_addr: u64, pdh_size: u32, chain_addr: u64, chain_size: u32) -> Self {
        Self {
            pdh_addr,
            pdh_size,
            chain_addr,
            chain_size,
            _phantom: PhantomData,
        }
    }
}

/// Request the CPU's unique identifier. Useful for obtaining
/// a certificate for the CEK public key.
///
/// (Chapter 5.13; Table 30)
#[repr(C, packed)]
pub struct GetIdentifier(pub [u8; 64], pub [u8; 64]);
