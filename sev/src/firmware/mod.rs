// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
mod linux;
mod types;

use super::*;
use std::fmt::Debug;

use bitflags::bitflags;

#[cfg(target_os = "linux")]
pub use linux::Firmware;

#[derive(Debug)]
pub enum Indeterminate<T: Debug> {
    Known(T),
    Unknown,
}

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),

    InvalidPlatformState,
    InvalidGuestState,
    InavlidConfig,
    InvalidLen,
    AlreadyOwned,
    InvalidCertificate,
    PolicyFailure,
    Inactive,
    InvalidAddress,
    BadSignature,
    BadMeasurement,
    AsidOwned,
    InvalidAsid,
    WbinvdRequired,
    DfFlushRequired,
    InvalidGuest,
    InvalidCommand,
    Active,
    HardwarePlatform,
    HardwareUnsafe,
    Unsupported,
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<std::io::Error> for Indeterminate<Error> {
    #[inline]
    fn from(error: std::io::Error) -> Indeterminate<Error> {
        Indeterminate::Known(error.into())
    }
}

impl From<u32> for Indeterminate<Error> {
    #[inline]
    fn from(error: u32) -> Indeterminate<Error> {
        Indeterminate::Known(match error {
            0 => std::io::Error::last_os_error().into(),
            1 => Error::InvalidPlatformState,
            2 => Error::InvalidGuestState,
            3 => Error::InavlidConfig,
            4 => Error::InvalidLen,
            5 => Error::AlreadyOwned,
            6 => Error::InvalidCertificate,
            7 => Error::PolicyFailure,
            8 => Error::Inactive,
            9 => Error::InvalidAddress,
            10 => Error::BadSignature,
            11 => Error::BadMeasurement,
            12 => Error::AsidOwned,
            13 => Error::InvalidAsid,
            14 => Error::WbinvdRequired,
            15 => Error::DfFlushRequired,
            16 => Error::InvalidGuest,
            17 => Error::InvalidCommand,
            18 => Error::Active,
            19 => Error::HardwarePlatform,
            20 => Error::HardwareUnsafe,
            21 => Error::Unsupported,
            _ => return Indeterminate::Unknown,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum State {
    Uninitialized,
    Initialized,
    Working,
}

bitflags! {
    #[derive(Default)]
    pub struct Flags: u32 {
        const OWNED           = 1 << 0;
        const ENCRYPTED_STATE = 1 << 8;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub build: Build,
    pub state: State,
    pub flags: Flags,
    pub guests: u32,
}

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
