// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::io::Error;
use std::marker::PhantomData;
use std::os::raw::{c_int, c_uint, c_ulong, c_void};
use std::os::unix::io::AsRawFd;
use std::ptr::null;

extern "C" {
    pub fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Code {
    Init = 0,
    EsInit,

    LaunchStart,
    LaunchUpdateData,
    LaunchUpdateVmsa,
    LaunchSecret,
    LaunchMeasure,
    LaunchFinish,

    SendStart,
    SendUpdateData,
    SendUpdateVmsa,
    SendFinish,

    ReceiveStart,
    ReceiveUpdateData,
    ReceiveUpdateVmsa,
    ReceiveFinish,

    GuestStatus,
    DebugDecrypt,
    DebugEncrypt,
    CertExport,
}

#[repr(C)]
pub struct Command {
    pub code: Code,
    pub data: u64,
    pub error: u32,
    pub fd: u32,
}

pub trait Ioctl {
    const REQUEST: c_ulong;

    fn ioctl(&self, fd: &impl AsRawFd) -> std::io::Result<c_uint> {
        let r = unsafe {
            ioctl(
                fd.as_raw_fd(),
                Self::REQUEST,
                self as *const _,
                null::<c_void>(),
            )
        };

        r.try_into().or_else(|_| Err(Error::last_os_error()))
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct EncryptOp<'a>(u64, PhantomData<&'a ()>);

impl<'a> Ioctl for EncryptOp<'a> {
    const REQUEST: c_ulong = 3221794490;
}

impl<'a> EncryptOp<'a> {
    pub fn new(cmd: &'a Command) -> Self {
        EncryptOp(cmd as *const _ as _, PhantomData)
    }
}
