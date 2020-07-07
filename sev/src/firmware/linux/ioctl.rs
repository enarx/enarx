// SPDX-License-Identifier: Apache-2.0

//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

use crate::firmware::types::*;
use iocuddle::*;

use std::marker::PhantomData;

/// The Linux kernel decides which SEV platform command to dispatch based
/// on its own enumeration values of the SEV commands. This trait
/// enforces that our type-safe ioctls also export the Linux
/// kernel enum ordinal value.
pub trait Code: 'static + Sized {
    /// The integer value that corresponds to the Linux kernel's
    /// enum value for a SEV ioctl.
    const CODE: u32;
}

macro_rules! code {
    (
        $(
            $iocty:ty = $val:expr
        ),* $(,)*
    ) => {
        $(
            impl $crate::firmware::linux::ioctl::Code for $iocty {
                const CODE: u32 = $val;
            }
        )*
    };
}

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
code! {
    PlatformReset = 0,
    PlatformStatus = 1,
    PekGen = 2,
}

const SEV: Group = Group::new(b'S');

/// Resets the SEV platform's persistent state.
pub const PLATFORM_RESET: Ioctl<WriteRead, &Command<PlatformReset>> = unsafe { SEV.write_read(0) };
/// Gathers a status report from the SEV firmware.
pub const PLATFORM_STATUS: Ioctl<WriteRead, &Command<PlatformStatus>> =
    unsafe { SEV.write_read(0) };
/// Generate a new Platform Endorsement Key (PEK).
pub const PEK_GEN: Ioctl<WriteRead, &Command<PekGen>> = unsafe { SEV.write_read(0) };

/// The Rust-flavored, FFI-friendly version of `struct kvm_sev_cmd` which is
/// used to pass arguments to the SEV ioctl implementation.
///
/// This struct is defined in the Linux kernel: include/uapi/linux/kvm.h
#[repr(C, packed)]
pub struct Command<'a, T: Code> {
    code: u32,
    data: u64,
    error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Code> Command<'a, T> {
    /// Create a new SEV command struct that encloses the lifetime of
    /// its data arguments.
    pub fn new(subcmd: &'a mut T) -> Self {
        Command {
            code: T::CODE,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}
