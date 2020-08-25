// SPDX-License-Identifier: Apache-2.0

use crate::impl_const_id;
use crate::launch::types::*;
use iocuddle::*;

use std::convert::TryInto;
use std::io::{Error, Result};
use std::marker::PhantomData;
use std::os::raw::{c_int, c_uint, c_ulong};
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
    LaunchFinish = 7,
}

const ENC_OP: u64 = 0xc008aeba;
const REG_REGION: u64 = 0x8010aebb;

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
/// Complete the SEV launch flow and transition the guest into
/// the ready state.
pub const LAUNCH_FINISH: Ioctl<WriteRead, &Command<LaunchFinish>> =
    unsafe { Ioctl::classic(ENC_OP) };

#[repr(C)]
pub struct EncryptedRegion<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> EncryptedRegion<'a> {
    pub fn new(region: &'a [u8]) -> Self {
        Self {
            addr: region.as_ptr() as _,
            len: region.len() as _,
            _phantom: PhantomData,
        }
    }

    pub fn ioctl(self, fd: &impl AsRawFd) -> Result<c_uint> {
        // iocuddle (correctly) won't allow the creation of a wrapper for
        // this ioctl where we supply a struct to the kernel  because it
        // is declared in the kernel as:
        //
        //     _IOR(KVMIO, 0xbb, struct kvm_enc_region)
        //
        // instead of as:
        //
        //     _IOW(KVMIO, 0xbb, struct kvm_enc_region)
        //
        // _IOR means the kernel is writing to a struct for us to read,
        // but the ioctl is meant to be used as _IOW which means *we* give
        // the kernel a struct for it to read from.
        extern "C" {
            fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        }

        let r = unsafe { ioctl(fd.as_raw_fd(), REG_REGION, &self as *const _ as c_ulong) };

        let res: c_uint = r.try_into().map_err(|_| Error::last_os_error())?;

        Ok(res)
    }
}

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
