// SPDX-License-Identifier: Apache-2.0

use crate::impl_const_id;
use crate::launch::types::*;
use iocuddle::*;

use std::io::Result;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    pub Id => u32;
    Init = 0,
    LaunchStart<'_> = 2,
    LaunchUpdateData<'_> = 3,
    LaunchSecret<'_> = 5,
    LaunchMeasure<'_> = 6,
}

const ENC_OP: u64 = 0xc008aeba;

// Note: the iocuddle::Ioctl::classic constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the SEV platform context.
pub const INIT: Ioctl<WriteRead, &Command<Init>> = unsafe { Ioctl::classic(ENC_OP) };
/// Create encrypted guest context.
pub const LAUNCH_START: Ioctl<WriteRead, &Command<LaunchStart>> = unsafe { Ioctl::classic(ENC_OP) };
/// Encrypt guest data with its VEK.
pub const LAUNCH_UPDATE_DATA: Ioctl<WriteRead, &Command<LaunchUpdateData>> =
    unsafe { Ioctl::classic(ENC_OP) };
/// Inject a secret into the guest.
pub const LAUNCH_SECRET: Ioctl<WriteRead, &Command<LaunchSecret>> =
    unsafe { Ioctl::classic(ENC_OP) };
/// Get the guest's measurement.
pub const LAUNCH_MEASUREMENT: Ioctl<WriteRead, &Command<LaunchMeasure>> =
    unsafe { Ioctl::classic(ENC_OP) };

#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    sev_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    pub fn from_mut(sev: &impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    pub fn from(sev: &impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }
}
