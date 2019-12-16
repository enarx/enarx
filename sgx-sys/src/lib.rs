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

mod ioctl;

use ioctl::Ioctl;
use std::fs::File;
use std::io::Result;
use std::mem::size_of_val;
use std::slice::from_raw_parts;

use sgx_traits::{Builder as BuilderTrait, Enclave as EnclaveTrait, Flags};
use sgx_types::page::{Class as PageClass, Flags as PageFlags, SecInfo};
use sgx_types::secs::Secs;
use sgx_types::sig;
use sgx_types::tcs::Tcs;
use sgx_types::Offset;

pub struct Builder(File);

impl BuilderTrait for Builder {
    type Enclave = Enclave;

    // Calls SGX_IOC_ENCLAVE_CREATE (ECREATE)
    fn new(secs: Secs) -> Result<Self> {
        let create = ioctl::sgx::Create::new(&secs);
        let file = File::open("/dev/sgx/enclave")?;
        create.ioctl(&file)?;
        Ok(Self(file))
    }

    unsafe fn add_tcs(&mut self, tcs: Tcs, offset: usize) -> Result<Offset<Tcs>> {
        let data = from_raw_parts(&tcs as *const Tcs as *const u8, size_of_val(&tcs));

        let si = SecInfo::new(PageFlags::R | PageFlags::W, PageClass::Tcs);
        self.add_slice(&data, offset, Flags::MEASURE, si)
            .map(|_| offset.into())
    }

    unsafe fn add_struct<T>(
        &mut self,
        data: T,
        offset: usize,
        flags: PageFlags,
    ) -> Result<Offset<T>> {
        #[repr(C, align(4096))]
        struct Paged<T>(T);

        let pages = Paged(data);
        let data = from_raw_parts(&pages as *const _ as *const u8, size_of_val(&pages));

        let si = SecInfo::new(flags, PageClass::Reg);
        self.add_slice(&data, offset, Flags::MEASURE, si)
            .map(|_| offset.into())
    }

    // Calls SGX_IOC_ENCLAVE_ADD_PAGES (EADD)
    unsafe fn add_slice(
        &mut self,
        data: &[u8],
        offset: usize,
        flags: Flags,
        secinfo: SecInfo,
    ) -> Result<Offset<[u8]>> {
        let addpages = ioctl::sgx::AddPages::new(data, offset, &secinfo, flags);
        addpages.ioctl(&self.0)?;
        Ok(offset.into())
    }

    // Calls SGX_IOC_ENCLAVE_INIT (EINIT)
    fn build(self, sig: sig::Signature) -> Result<Self::Enclave> {
        let init = ioctl::sgx::Init::new(&sig);
        init.ioctl(&self.0)?;
        Ok(Enclave(self.0))
    }
}

pub struct Enclave(File);

impl<'e> EnclaveTrait for Enclave {
    unsafe fn enter(&self, _: &mut Offset<Tcs>) -> Result<()> {
        Err(std::io::ErrorKind::Other.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sgx_types::{attr, misc};

    #[cfg_attr(not(has_sgx), ignore)]
    #[test]
    fn enclave_create() {
        let contents = sig::Contents::new(
            misc::MiscSelect::default(),
            attr::Attributes::default(),
            [0u8; 32],
            0,
            0,
        );

        let secs = Secs::new(8192, 8192, 4096, &contents);

        Builder::new(secs).unwrap();
    }
}
