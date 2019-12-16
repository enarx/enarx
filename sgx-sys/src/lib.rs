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

use sgx_traits::{Builder as BuilderTrait, Enclave as EnclaveTrait, Flags};
use sgx_types::{page, secs, sig};

pub struct Builder(File);

impl BuilderTrait for Builder {
    type Enclave = Enclave;

    // Calls SGX_IOC_ENCLAVE_CREATE (ECREATE)
    fn new(secs: secs::Secs) -> Result<Self> {
        let create = ioctl::sgx::Create::new(&secs);
        let file = File::open("/dev/sgx/enclave")?;
        create.ioctl(&file)?;
        Ok(Self(file))
    }

    // Calls SGX_IOC_ENCLAVE_ADD_PAGES (EADD and EEXTEND)
    unsafe fn add(
        &mut self,
        offset: usize,
        data: &[u8],
        flags: Flags,
        secinfo: page::SecInfo,
    ) -> Result<()> {
        let addpages = ioctl::sgx::AddPages::new(data, offset, &secinfo, flags);
        addpages.ioctl(&self.0)?;
        Ok(())
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
    unsafe fn enter(&self, _: usize) -> Result<()> {
        Err(std::io::ErrorKind::Other.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sgx_types::{attr, misc};

    const CONTENTS: sig::Contents = sig::Contents::new(
        misc::MiscSelect::default(),
        attr::Attributes::default(),
        [0u8; 32],
        0,
        0,
    );

    #[cfg_attr(not(has_sgx), ignore)]
    #[test]
    fn create() {
        let secs = secs::Secs::new(8192, 8192, 4096, &contents);
        Builder::new(secs).unwrap();
    }

    #[cfg_attr(not(has_sgx), ignore)]
    #[test]
    fn add() {
        let secs = secs::Secs::new(8192, 8192, 4096, &contents);
        Builder::new(secs).unwrap();
    }
}
