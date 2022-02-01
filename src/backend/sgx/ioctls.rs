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
pub const PAGE_MODP: Ioctl<Write, &PageModPerms> = unsafe { SGX.write(0x05) };
pub const PAGE_MODT: Ioctl<Write, &PageModType> = unsafe { SGX.write(0x06) };
pub const PAGE_REMOVE: Ioctl<Write, &PageRemove> = unsafe { SGX.write(0x07) };

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
pub struct PageModPerms {
    pub offset: u64,
    pub length: u64,
    pub prot: u64,
    pub result: u64,
    pub count: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct PageModType {
    pub offset: u64,
    pub length: u64,
    pub kind: u64,
    pub result: u64,
    pub count: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct PageRemove {
    pub offset: u64,
    pub length: u64,
    pub count: u64,
}
