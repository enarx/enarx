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
use std::mem::size_of;

mod ioctl;
pub mod tcs;
pub mod secs;
pub mod sigstruct;

pub struct EnclaveBuilder(File);
pub struct Enclave(File);

pub enum Page<'a> {
    Tcs(&'a tcs::Tcs),
    Regular {
        data: &'a [u8],
        perms: ioctl::sgx::PagePerms,
        flags: ioctl::sgx::PageFlags,
    },
}

impl EnclaveBuilder {
    // Calls SGX_IOC_ENCLAVE_CREATE (ECREATE)
    pub fn new(secs: &secs::Secs) -> Result<EnclaveBuilder> {
        let create = ioctl::sgx::Create::new(secs);
        let file = File::open("/dev/sgx/enclave")?;
        create.ioctl(&file)?;
        Ok(Self(file))
    }

    // Calls SGX_IOC_ENCLAVE_ADD_PAGES (EADD)
    pub fn add_pages(self, page: Page, offset: usize) -> Result<Self> {
        use ioctl::sgx;

        let (data, si, flags) = match &page {
            Page::Tcs(tcs) => {
                let data = unsafe {
                    std::slice::from_raw_parts(
                        *tcs as *const tcs::Tcs as *const u8,
                        size_of::<tcs::Tcs>()
                    )
                };
                
                let si = sgx::SecInfo::new(
                    sgx::PagePerms::READ | sgx::PagePerms::WRITE,
                    sgx::PageType::Tcs
                );

                (data, si, sgx::PageFlags::MEASURE)
            },

            Page::Regular { data, perms, flags } => {
                (*data, sgx::SecInfo::new(*perms, sgx::PageType::Reg), *flags)
            },
        };

        let addpages = sgx::AddPages::new(data, offset, &si, flags);
        addpages.ioctl(&self.0)?;
        Ok(self)
    }

    // Calls SGX_IOC_ENCLAVE_INIT (EINIT)
    pub fn build(self, ss: &mut sigstruct::SigStruct) -> Result<Enclave> {
        let init = ioctl::sgx::Init::new(ss);
        init.ioctl(&self.0)?;
        Ok(Enclave(self.0))
    }
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
        secs.xfrm = secs::Xfrm::X87 | secs::Xfrm::SSE;
        EnclaveBuilder::new(&secs).unwrap();
    }
}
