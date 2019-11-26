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

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![deny(clippy::all)]
#![allow(clippy::identity_op)]

use ioctl::Ioctl;
use std::fs::File;
use std::io::Result;

mod ioctl;
pub mod secs;

pub struct Enclave(File);

impl Enclave {
    pub fn create(secs: &secs::Secs) -> Result<Self> {
        let create = ioctl::sgx::Create::new(secs);
        let file = File::open("/dev/sgx/enclave")?;
        create.ioctl(&file)?;
        Ok(Self(file))
    }

    // EADD and EEXTEND
    //pub fn add_pages(&self, secs: &SgxSecs, tcs: &SgxTcs, sigstruct: &SgxSigStruct) -> Result<()> {
    // wrap Rust version of SGX_IOC_ENCLAVE_ADD_PAGES
    //}

    // EINIT
    //pub fn init(&self, sigstruct: &mut SgxSigStruct, secs: &SgxSecs, lepubkeyhash: &SgxLePubKeyHash) -> std::io::Result<()> {
    // wrap Rust version of SGX_IOC_ENCLAVE_INIT
    //}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn enclave_create() {
        let mut secs = secs::Secs::default();
        secs.size = 8192;
        secs.base = 8192;
        secs.ssa_frame_size = 4096;
        secs.attributes = secs::Attributes::MODE_64_BIT;
        secs.miscselect = secs::MiscSelect::EXINFO;
        secs.xfrm = (secs::Xfrm::X87 | secs::Xfrm::SSE);
        Enclave::create(&secs).unwrap();
    }
}
