// SPDX-License-Identifier: Apache-2.0

//! Enclave object

use std::fs::{File, OpenOptions};
use std::io::Result;
use std::marker::PhantomData;

use iocuddle::{Group, Ioctl, Write, WriteRead};
use sgx::page::{SecInfo, Secs};
use sgx::signature::Signature;

/// Wraps an enclave file descriptor.
pub struct Enclave(File);

impl From<Enclave> for File {
    fn from(enclave: Enclave) -> File {
        enclave.0
    }
}

impl Enclave {
    /// The path of the device file.
    pub const DEVICE: &'static str = "/dev/sgx_enclave";

    const SGX: Group = Group::new(0xA4);

    /// Create a new instance.
    pub fn new() -> Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(Enclave::DEVICE)
            .map(Self)
    }

    pub fn try_clone(&mut self) -> Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    /// ENCLS[ECREATE] wrapper
    pub fn create(&mut self, secs: &Secs) -> Result<()> {
        const CREATE: Ioctl<Write, &'static Create<'static>> = unsafe { Enclave::SGX.write(0x00) };
        CREATE
            .ioctl(&mut self.0, &Create(secs as *const _ as _, PhantomData))
            .map(|_| ())
    }

    /// ENCLS[EADD] wrapper
    pub fn add_pages(
        &mut self,
        bytes: &[u8],
        offset: usize,
        secinfo: &SecInfo,
        measure: bool,
    ) -> Result<()> {
        const ADD_PAGES: Ioctl<WriteRead, &'static AddPages<'static>> =
            unsafe { Enclave::SGX.write_read(0x01) };
        ADD_PAGES
            .ioctl(
                &mut self.0,
                &mut AddPages::new(bytes, offset, secinfo, measure),
            )
            .map(|_| ())
    }

    /// ENCLS[EINIT] wrapper
    pub fn init(&mut self, signature: &Signature) -> Result<()> {
        const INIT: Ioctl<Write, &'static Init<'static>> = unsafe { Enclave::SGX.write(0x02) };
        INIT.ioctl(&mut self.0, &Init::new(signature)).map(|_| ())
    }

    /// ENCLS[EMODPR] wrapper
    pub fn restrict_permissions(
        &mut self,
        offset: usize,
        length: usize,
        secinfo: &SecInfo,
    ) -> Result<()> {
        const RESTRICT_PERMISSIONS: Ioctl<WriteRead, &'static RestrictPermissions<'static>> =
            unsafe { Enclave::SGX.write_read(0x05) };
        RESTRICT_PERMISSIONS
            .ioctl(
                &mut self.0,
                &mut RestrictPermissions::new(offset, length, secinfo),
            )
            .map(|_| ())
    }

    /// ENCLS[EMODT] wrapper
    pub fn modify_types(&mut self, offset: usize, length: usize, secinfo: &SecInfo) -> Result<()> {
        const MODIFY_TYPES: Ioctl<WriteRead, &'static ModifyTypes<'static>> =
            unsafe { Enclave::SGX.write_read(0x06) };
        MODIFY_TYPES
            .ioctl(&mut self.0, &mut ModifyTypes::new(offset, length, secinfo))
            .map(|_| ())
    }

    /// ENCLS[EREMOVE] wrapper
    pub fn remove_pages(&mut self, offset: usize, length: usize) -> Result<()> {
        const REMOVE_PAGES: Ioctl<WriteRead, &'static RemovePages> =
            unsafe { Enclave::SGX.write_read(0x07) };
        REMOVE_PAGES
            .ioctl(&mut self.0, &mut RemovePages::new(offset, length))
            .map(|_| ())
    }
}

struct Create<'a>(u64, PhantomData<&'a ()>);

#[repr(C)]
struct AddPages<'a> {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> AddPages<'a> {
    fn new(bytes: &'a [u8], offset: usize, secinfo: &'a SecInfo, measure: bool) -> Self {
        const MEASURE: u64 = 1 << 0;
        let flags = match measure {
            true => MEASURE,
            false => 0,
        };
        Self {
            src: bytes.as_ptr() as _,
            offset: offset as _,
            length: bytes.len() as _,
            secinfo: secinfo as *const _ as _,
            flags,
            count: 0,
            phantom: PhantomData,
        }
    }
}

#[repr(C)]
pub struct Init<'a>(u64, PhantomData<&'a ()>);

impl<'a> Init<'a> {
    fn new(sig: &'a Signature) -> Self {
        Init(sig as *const _ as _, PhantomData)
    }
}

#[repr(C)]
pub struct RestrictPermissions<'a> {
    offset: u64,
    length: u64,
    secinfo: u64,
    result: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> RestrictPermissions<'a> {
    fn new(offset: usize, length: usize, secinfo: &'a SecInfo) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            secinfo: secinfo as *const _ as _,
            result: 0,
            count: 0,
            phantom: PhantomData,
        }
    }
}

#[repr(C)]
struct ModifyTypes<'a> {
    offset: u64,
    length: u64,
    secinfo: u64,
    result: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> ModifyTypes<'a> {
    fn new(offset: usize, length: usize, secinfo: &'a SecInfo) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            secinfo: secinfo as *const _ as _,
            result: 0,
            count: 0,
            phantom: PhantomData,
        }
    }
}

#[repr(C)]
struct RemovePages {
    offset: u64,
    length: u64,
    count: u64,
}

impl RemovePages {
    fn new(offset: usize, length: usize) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            count: 0,
        }
    }
}

#[cfg(all(test, host_can_test_sgx))]
mod tests {
    use crate::backend::sgx::enclave::Enclave;
    use sgx::page::{Flags, SecInfo};

    #[test]
    fn restrict_permissions() {
        let mut enclave = Enclave::new().unwrap();
        let secinfo = SecInfo::reg(Flags::empty());
        assert_eq!(
            enclave
                .restrict_permissions(0, 0, &secinfo)
                .map_err(|e| e.raw_os_error()),
            Err(Some(libc::EINVAL))
        );
    }

    #[test]
    fn modify_types() {
        let mut enclave = Enclave::new().unwrap();
        let secinfo = SecInfo::reg(Flags::empty());
        assert_eq!(
            enclave
                .modify_types(0, 0, &secinfo)
                .map_err(|e| e.raw_os_error()),
            Err(Some(libc::EINVAL))
        );
    }

    #[test]
    fn remove_pages() {
        let mut enclave = Enclave::new().unwrap();
        assert_eq!(
            enclave.remove_pages(0, 0).map_err(|e| e.raw_os_error()),
            Err(Some(libc::EINVAL))
        );
    }
}
