// Copyright 2019 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
pub const ENCLAVE_SET_ATTRIBUTE: Ioctl<Write, &SetAttribute> = unsafe { SGX.write(0x03) };

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
    pub fn new(data: &'a [u8], offset: usize, secinfo: &'a page::SecInfo, flags: Flags) -> Self {
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
    use rstest::*;
    use sgx_types::{attr, misc, page};
    use std::fs::File;

    #[fixture]
    pub fn file() -> File {
        File::open("/dev/sgx/enclave").unwrap()
    }

    #[fixture]
    pub fn created(file: File) -> File {
        let contents = sig::Contents::new(
            misc::MiscSelect::default(),
            misc::MiscSelect::default(),
            attr::Attributes::default(),
            attr::Attributes::default(),
            [0u8; 32],
            0,
            0,
        );

        let secs = secs::Secs::new(0, secs::Secs::SIZE_MAX, 4096, &contents);

        let mut file = file; // Work around an erronious compiler warning...
        let create = Create::new(&secs);
        ENCLAVE_CREATE.ioctl(&mut file, &create).unwrap();

        file
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
        ]
    )]
    fn test(mut created: File, flags: Flags, perms: page::Flags) {
        #[repr(C, align(4096))]
        struct Page([u8; 4096]);

        let page = Page([0u8; 4096]);

        // Add a TCS page
        let si = page::SecInfo::tcs();
        eprintln!("TCS: {:?}, {:?}", flags, si);
        let mut addpages = AddPages::new(&page.0, 0x0000, &si, flags);
        ENCLAVE_ADD_PAGES
            .ioctl(&mut created, &mut addpages)
            .unwrap();

        // Add a REG page
        let si = page::SecInfo::reg(perms);
        eprintln!("REG: {:?}, {:?}", flags, si);
        let mut addpages = AddPages::new(&page.0, 0x1000, &si, flags);
        ENCLAVE_ADD_PAGES
            .ioctl(&mut created, &mut addpages)
            .unwrap();

        // Initialize
        //ENCLAVE_INIT.ioctl(&mut created, &Init::new(&sig)).unwrap();
    }
}
