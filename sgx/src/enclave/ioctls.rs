// SPDX-License-Identifier: Apache-2.0

//! This module implements Intel SGX-related IOCTLs using the iocuddle crate.
//! All references to Section or Tables are from
//! https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![cfg(feature = "std")]

use std::marker::PhantomData;

use crate::types::{page::SecInfo, secs, sig};
use bitflags::bitflags;
use iocuddle::*;
use primordial::Page;

const SGX: Group = Group::new(0xA4);

/// IOCTL identifier for ECREATE (see Section 41-21)
pub const ENCLAVE_CREATE: Ioctl<Write, &Create> = unsafe { SGX.write(0x00) };

/// IOCTL identifier for EADD (see Section 41-11)
pub const ENCLAVE_ADD_PAGES: Ioctl<WriteRead, &AddPages> = unsafe { SGX.write_read(0x01) };

/// IOCTL identifier for EINIT (see Section 41-35)
pub const ENCLAVE_INIT: Ioctl<Write, &Init> = unsafe { SGX.write(0x02) };

//pub const ENCLAVE_SET_ATTRIBUTE: Ioctl<Write, &SetAttribute> = unsafe { SGX.write(0x03) };

bitflags! {
    /// WIP
    pub struct Flags: u64 {
        /// Indicates whether a page has been measured.
        const MEASURE = 1 << 0;
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for creating a new enclave from SECS
pub struct Create<'a>(u64, PhantomData<&'a ()>);

impl<'a> Create<'a> {
    /// A new Create struct wraps an SECS struct from the sgx-types crate.
    pub fn new(secs: &'a secs::Secs) -> Self {
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
    flags: Flags,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> AddPages<'a> {
    /// Creates a new AddPages struct for a page at a certain offset
    pub fn new(data: &'a [Page], offset: usize, secinfo: &'a SecInfo, flags: Flags) -> Self {
        let data = unsafe { data.align_to::<u8>().1 };

        Self {
            src: data.as_ptr() as _,
            offset: offset as _,
            length: data.len() as _,
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
    pub fn new(sig: &'a sig::Signature) -> Self {
        Init(sig as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
/// Struct for setting enclave attributes - WIP - ERESUME? EREMOVE?
pub struct SetAttribute<'a>(u64, PhantomData<&'a ()>);

impl<'a> SetAttribute<'a> {
    #[allow(dead_code)]
    /// A new SetAttribute struct must wrap a file descriptor.
    pub fn new(fd: &'a impl std::os::unix::io::AsRawFd) -> Self {
        SetAttribute(fd.as_raw_fd() as _, PhantomData)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::File;
    use std::num::NonZeroU32;

    use crate::{
        crypto::Hasher,
        types::{page::Flags as Perms, secs},
    };
    use lset::Span;
    use openssl::{bn, pkey, rsa};
    use rstest::*;

    #[fixture]
    fn file() -> File {
        File::open("/dev/sgx/enclave").unwrap()
    }

    #[fixture]
    fn key() -> rsa::Rsa<pkey::Private> {
        let e = bn::BigNum::from_u32(3u32).unwrap();
        rsa::Rsa::generate_with_e(3072, &e).unwrap()
    }

    #[cfg_attr(not(has_sgx), ignore)]
    #[rstest(
        flags => [Flags::empty(), Flags::MEASURE],
        perms => [
            Perms::empty(),
            Perms::R,
            Perms::R | Perms::W,
            Perms::R | Perms::X,
            Perms::R | Perms::W | Perms::X,
        ],
    )]
    fn test(mut file: File, key: rsa::Rsa<pkey::Private>, flags: Flags, perms: Perms) {
        const SSA_PAGES: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };
        const BASE_ADDR: usize = 0x0000;
        const TCS_OFFSET: usize = 0x0000;
        const REG_OFFSET: usize = 0x1000;

        let page = [Page::default()];
        let span = Span {
            start: BASE_ADDR,
            count: secs::Secs::max_enc_size().unwrap().get(),
        };

        // Create the hasher.
        let measure = flags.contains(Flags::MEASURE);
        let mut hasher = Hasher::new(span.count, SSA_PAGES);

        // Create the enclave.
        let secs = secs::Secs::new(span, SSA_PAGES, None);
        let create = Create::new(&secs);
        ENCLAVE_CREATE.ioctl(&mut file, &create).unwrap();

        // Add a TCS page
        let si = SecInfo::tcs();
        let mut ap = AddPages::new(&page, TCS_OFFSET, &si, flags);
        ENCLAVE_ADD_PAGES.ioctl(&mut file, &mut ap).unwrap();
        hasher.add(&page, TCS_OFFSET, SecInfo::tcs(), measure);

        // Add a REG page
        let si = SecInfo::reg(perms);
        let mut ap = AddPages::new(&page, REG_OFFSET, &si, flags);
        ENCLAVE_ADD_PAGES.ioctl(&mut file, &mut ap).unwrap();
        hasher.add(&page, REG_OFFSET, SecInfo::reg(perms), measure);

        // Initialize the enclave.
        let author = sig::Author::new(0, 0);
        let sig = hasher.finish(None).sign(author, key).unwrap();
        ENCLAVE_INIT.ioctl(&mut file, &Init::new(&sig)).unwrap();
    }
}
