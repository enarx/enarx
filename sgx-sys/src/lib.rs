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
use std::marker::PhantomData;
use std::mem::size_of_val;

use sgx_traits::{Builder as BuilderTrait, Enclave as EnclaveTrait, Flags};
use sgx_types::secinfo::{Flags as Perms, PageType, SecInfo};
use sgx_types::secs::Secs;
use sgx_types::sigstruct::SigStruct;
use sgx_types::tcs::Tcs;
use sgx_types::Offset;

pub struct Builder<'b>(File, PhantomData<&'b ()>);

impl<'b> BuilderTrait<'b> for Builder<'b> {
    type Enclave = Enclave<'b>;

    // Calls SGX_IOC_ENCLAVE_CREATE (ECREATE)
    fn new(secs: Secs) -> Result<Self> {
        let create = ioctl::sgx::Create::new(&secs);
        let file = File::open("/dev/sgx/enclave")?;
        create.ioctl(&file)?;
        Ok(Self(file, PhantomData))
    }

    fn add_tcs(&mut self, tcs: Tcs, offset: usize) -> Result<Offset<'b, Tcs>> {
        let data = unsafe {
            std::slice::from_raw_parts(&tcs as *const Tcs as *const u8, size_of_val(&tcs))
        };

        let si = SecInfo::new(Perms::R | Perms::W, PageType::Tcs);
        self.add_slice(&data, offset, Flags::MEASURE, si)
            .map(|_| unsafe { Offset::new(offset) })
    }

    fn add_struct<T>(&mut self, data: T, offset: usize, perms: Perms) -> Result<Offset<'b, T>> {
        #[repr(C, align(4096))]
        struct Paged<T>(T);

        let pages = Paged(data);
        let data = unsafe {
            std::slice::from_raw_parts(&pages as *const _ as *const u8, size_of_val(&pages))
        };

        let si = SecInfo::new(perms, PageType::Reg);
        self.add_slice(&data, offset, Flags::MEASURE, si)
            .map(|_| unsafe { Offset::new(offset) })
    }

    // Calls SGX_IOC_ENCLAVE_ADD_PAGES (EADD)
    fn add_slice(
        &mut self,
        data: &[u8],
        offset: usize,
        flags: Flags,
        secinfo: SecInfo,
    ) -> Result<Offset<'b, ()>> {
        let addpages = ioctl::sgx::AddPages::new(data, offset, &secinfo, flags);
        addpages.ioctl(&self.0)?;
        Ok(unsafe { Offset::new(offset) })
    }

    // Calls SGX_IOC_ENCLAVE_INIT (EINIT)
    fn build(self, ss: SigStruct) -> Result<Self::Enclave> {
        let init = ioctl::sgx::Init::new(&ss);
        init.ioctl(&self.0)?;
        Ok(Enclave(self.0, PhantomData))
    }
}

pub struct Enclave<'e>(File, PhantomData<&'e ()>);

impl<'e> EnclaveTrait<'e> for Enclave<'e> {
    fn enter(&self, _: &mut Offset<'e, Tcs>) -> Result<()> {
        Err(std::io::ErrorKind::Other.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg_attr(not(has_sgx), ignore)]
    #[test]
    fn enclave_create() {
        use sgx_types::*;

        let mut secs = Secs::default();
        secs.size = 8192;
        secs.base = 8192;
        secs.ssa_frame_size = 4096;
        secs.xfrm = xfrm::Xfrm::default();
        Builder::new(secs).unwrap();
    }
}
