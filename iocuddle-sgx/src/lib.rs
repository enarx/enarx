// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
#![allow(clippy::identity_op)]

use std::marker::PhantomData;

use bitflags::bitflags;
use iocuddle::*;
use sgx_types::{page, secs, sig};

const SGX: Group = Group::new(0xA4);
pub const ENCLAVE_CREATE: Ioctl<Write, &Create> = unsafe { SGX.write(0x00) };
pub const ENCLAVE_ADD_PAGES: Ioctl<WriteRead, &AddPages> = unsafe { SGX.write_read(0x01) };
pub const ENCLAVE_INIT: Ioctl<Write, &Init> = unsafe { SGX.write(0x02) };
//pub const ENCLAVE_SET_ATTRIBUTE: Ioctl<Write, &SetAttribute> = unsafe { SGX.write(0x03) };

bitflags! {
    pub struct Flags: u64 {
        const MEASURE = 1 << 0;
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Create<'a>(u64, PhantomData<&'a ()>);

impl<'a> Create<'a> {
    pub fn new(secs: &'a secs::Secs) -> Self {
        Create(secs as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
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
    pub fn new(data: &'a [u8], offset: u64, secinfo: &'a page::SecInfo, flags: Flags) -> Self {
        Self {
            src: data.as_ptr() as _,
            offset,
            length: data.len() as _,
            secinfo: secinfo as *const _ as _,
            flags,
            count: 0,
            phantom: PhantomData,
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Init<'a>(u64, PhantomData<&'a ()>);

impl<'a> Init<'a> {
    pub fn new(sig: &'a sig::Signature) -> Self {
        Init(sig as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SetAttribute<'a>(u64, PhantomData<&'a ()>);

impl<'a> SetAttribute<'a> {
    pub fn new(fd: &'a impl std::os::unix::io::AsRawFd) -> Self {
        SetAttribute(fd.as_raw_fd() as _, PhantomData)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::convert::TryFrom;
    use std::fs::File;
    use std::num::NonZeroU32;

    use openssl::{bn, pkey, rsa};
    use rstest::*;
    use sgx_crypto::{Hasher, Signature};
    use sgx_types::{attr, isv, misc, page};

    #[repr(C, align(4096))]
    struct Page([u8; 4096]);

    const PAGE: Page = Page([0u8; 4096]);

    #[fixture]
    fn file() -> File {
        File::open("/dev/sgx/enclave").unwrap()
    }

    #[fixture]
    fn key() -> rsa::Rsa<pkey::Private> {
        let e = bn::BigNum::try_from(3u32).unwrap();
        rsa::Rsa::generate_with_e(3072, &e).unwrap()
    }

    #[cfg_attr(not(has_sgx), ignore)]
    #[rstest(
        flags => [Flags::empty(), Flags::MEASURE],
        perms => [
            page::Flags::empty(),
            page::Flags::R,
            page::Flags::R | page::Flags::W,
            page::Flags::R | page::Flags::X,
            page::Flags::R | page::Flags::W | page::Flags::X,
        ],
    )]
    fn test(mut file: File, key: rsa::Rsa<pkey::Private>, flags: Flags, perms: page::Flags) {
        const TCS_OFFSET: u64 = 0x0000;
        const REG_OFFSET: u64 = 0x1000;
        const BASE_ADDR: u64 = 0x0000;
        const SSA_SIZE: u32 = 0x1000;

        let spec = secs::Spec {
            enc_size: unsafe { secs::Spec::max_enc_size().unwrap() },
            ssa_size: NonZeroU32::new(SSA_SIZE).unwrap(),
        };

        // Hash all the pages
        let measure = flags.contains(Flags::MEASURE);
        let mut hasher = Hasher::from(&spec);
        hasher.add(TCS_OFFSET, &PAGE.0, measure, page::SecInfo::tcs());
        hasher.add(REG_OFFSET, &PAGE.0, measure, page::SecInfo::reg(perms));
        let hash = hasher.finish();

        // Make the SECS page
        let author = sig::Vendor::INTEL.author(0, 0);
        let contents = sig::Contents::new(
            misc::MiscSelect::default().into(),
            attr::Attributes::default().into(),
            hash,
            isv::ProdId::new(0),
            isv::Svn::new(0),
        );
        let sig = sig::Signature::sign(author, contents, key).unwrap();
        let secs = sig.secs(BASE_ADDR, spec);

        // Create the enclave
        let create = Create::new(&secs);
        ENCLAVE_CREATE.ioctl(&mut file, &create).unwrap();

        // Add a TCS page
        let si = page::SecInfo::tcs();
        let mut ap = AddPages::new(&PAGE.0, TCS_OFFSET, &si, flags);
        ENCLAVE_ADD_PAGES.ioctl(&mut file, &mut ap).unwrap();

        // Add a REG page
        let si = page::SecInfo::reg(perms);
        let mut ap = AddPages::new(&PAGE.0, REG_OFFSET, &si, flags);
        ENCLAVE_ADD_PAGES.ioctl(&mut file, &mut ap).unwrap();

        // Initialize
        ENCLAVE_INIT.ioctl(&mut file, &Init::new(&sig)).unwrap();
    }
}
