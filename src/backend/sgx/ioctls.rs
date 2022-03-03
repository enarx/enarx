// SPDX-License-Identifier: Apache-2.0

//! This module implements Intel SGX-related IOCTLs using the iocuddle crate.
//! All references to Section or Tables are from
//! [Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 3D: System Programming Guide, Part 4](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf)

#![allow(dead_code)]

use std::marker::PhantomData;

use iocuddle::*;
use sgx::page::{SecInfo, Secs};
use sgx::signature::Signature;

const SGX: Group = Group::new(0xA4);

/// IOCTL identifier for ECREATE (see Section 41-21)
pub const ENCLAVE_CREATE: Ioctl<Write, &Create<'_>> = unsafe { SGX.write(0x00) };

/// IOCTL identifier for EADD (see Section 41-11)
pub const ENCLAVE_ADD_PAGES: Ioctl<WriteRead, &AddPages<'_>> = unsafe { SGX.write_read(0x01) };

/// IOCTL identifier for EINIT (see Section 41-35)
pub const ENCLAVE_INIT: Ioctl<Write, &Init<'_>> = unsafe { SGX.write(0x02) };

pub const ENCLAVE_SET_ATTRIBUTE: Ioctl<Write, &SetAttribute<'_>> = unsafe { SGX.write(0x03) };

/// SGX_IOC_VEPC_REMOVE_ALL (0x04) is not used by Enarx.

/// SGX_IOC_ENCLAVE_RELAX_PERMISSIONS
pub const ENCLAVE_RELAX_PERMISSIONS: Ioctl<WriteRead, &RelaxPermissions<'_>> =
    unsafe { SGX.write_read(0x05) };

/// SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS
pub const ENCLAVE_RESTRICT_PERMISSIONS: Ioctl<WriteRead, &RestrictPermissions<'_>> =
    unsafe { SGX.write_read(0x06) };

#[repr(C)]
#[derive(Debug)]
/// Struct for creating a new enclave from SECS
pub struct Create<'a>(u64, PhantomData<&'a ()>);

impl<'a> Create<'a> {
    /// A new Create struct wraps an SECS struct from the sgx-types crate.
    pub fn new(secs: &'a Secs) -> Self {
        Create(secs as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for adding pages to an enclave
pub struct AddPages<'a> {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> AddPages<'a> {
    /// Creates a new AddPages struct for a page at a certain offset
    pub fn new(bytes: &'a [u8], offset: usize, secinfo: &'a SecInfo, measure: bool) -> Self {
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

    #[allow(dead_code)]
    /// WIP
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for initializing an enclave
pub struct Init<'a>(u64, PhantomData<&'a ()>);

impl<'a> Init<'a> {
    /// A new Init struct must wrap a Signature from the sgx-types crate.
    pub fn new(sig: &'a Signature) -> Self {
        Init(sig as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for setting enclave attributes - WIP - ERESUME? EREMOVE?
pub struct SetAttribute<'a>(u64, PhantomData<&'a ()>);

impl<'a> SetAttribute<'a> {
    #[allow(dead_code)]
    /// A new SetAttribute struct must wrap a file descriptor.
    pub fn new(fd: &'a impl std::os::unix::io::AsRawFd) -> Self {
        SetAttribute(fd.as_raw_fd() as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// SGX_IOC_ENCLAVE_RELAX_PERMISSIONS parameter structure
pub struct RelaxPermissions<'a> {
    /// In: starting page offset
    offset: u64,
    /// In: length of the address range (multiple of the page size)
    length: u64,
    /// In: SECINFO containing the relaxed permissions
    secinfo: u64,
    /// Out: length of the address range successfully changed
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> RelaxPermissions<'a> {
    /// Create a new RelaxPermissions instance.
    pub fn new(offset: usize, length: usize, secinfo: &'a SecInfo) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            secinfo: secinfo as *const _ as _,
            count: 0,
            phantom: PhantomData,
        }
    }

    /// Read count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[repr(C)]
#[derive(Debug)]
/// SGX_IOC_ENCLAVE_RELAX_PERMISSIONS parameter structure
pub struct RestrictPermissions<'a> {
    /// In: starting page offset
    offset: u64,
    /// In: length of the address range (multiple of the page size)
    length: u64,
    /// In: SECINFO containing the relaxed permissions
    secinfo: u64,
    /// Out: ENCLU[EMODPR] return value
    result: u64,
    /// Out: length of the address range successfully changed
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> RestrictPermissions<'a> {
    /// Create a new RestrictPermissions instance.
    pub fn new(offset: usize, length: usize, secinfo: &'a SecInfo) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            secinfo: secinfo as *const _ as _,
            result: 0,
            count: 0,
            phantom: PhantomData,
        }
    }

    /// Read result attribute.
    pub fn result(&self) -> u64 {
        self.count
    }

    /// Read count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[cfg(all(test, host_can_test_sgx))]
mod tests {
    use super::*;

    #[test]
    fn relax_permissions() {
        use sgx::page::{Flags, SecInfo};
        use std::fs::OpenOptions;

        let mut device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")
            .unwrap();

        let secinfo = SecInfo::reg(Flags::empty());
        let mut parameters = RelaxPermissions::new(0, 0, &secinfo);

        let ret = match ENCLAVE_RELAX_PERMISSIONS.ioctl(&mut device_file, &mut parameters) {
            Ok(_) => 0,
            Err(err) => err.raw_os_error().unwrap(),
        };

        assert_eq!(ret, libc::EINVAL);
    }

    #[test]
    fn restrict_permissions() {
        use sgx::page::{Flags, SecInfo};
        use std::fs::OpenOptions;

        let mut device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")
            .unwrap();

        let secinfo = SecInfo::reg(Flags::empty());
        let mut parameters = RestrictPermissions::new(0, 0, &secinfo);

        let ret = match ENCLAVE_RESTRICT_PERMISSIONS.ioctl(&mut device_file, &mut parameters) {
            Ok(_) => 0,
            Err(err) => err.raw_os_error().unwrap(),
        };

        assert_eq!(ret, libc::EINVAL);
    }
}
