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
#![allow(clippy::unreadable_literal)]

use std::io::Result;

use openssl::sha;
use sgx_types::{page, secs};

pub struct Hasher(sha::Sha256);

impl Hasher {
    // Mimics call to SGX_IOC_ENCLAVE_CREATE (ECREATE)
    pub fn new(secs: secs::Secs) -> Self {
        const ECREATE: u64 = 0x0045544145524345;

        let mut sha256 = sha::Sha256::new();
        sha256.update(&ECREATE.to_le_bytes());
        sha256.update(&secs.ssa_size().to_le_bytes());
        sha256.update(&secs.size().to_le_bytes());
        sha256.update(&[0u8; 44]); // Reserved

        Self(sha256)
    }

    // Mimics call to SGX_IOC_ENCLAVE_ADD_PAGES (EADD and EEXTEND)
    pub unsafe fn add(
        &mut self,
        offset: usize,
        data: &[u8],
        flags: sgx_traits::Flags,
        secinfo: page::SecInfo,
    ) {
        const EEXTEND: u64 = 0x00444E4554584545;
        const EADD: u64 = 0x0000000044444145;

        let offset = offset as u64;

        // Hash for the EADD instruction.
        self.0.update(&EADD.to_le_bytes());
        self.0.update(&(offset as u64).to_le_bytes());
        self.0.update(&secinfo.as_ref()[..48]);

        // Hash for the EEXTEND instruction.
        if let sgx_traits::Flags::MEASURE = flags {
            for i in 0..16 {
                let poff = i * 256;
                let eoff = offset + poff as u64;

                self.0.update(&EEXTEND.to_le_bytes());
                self.0.update(&eoff.to_le_bytes());
                self.0.update(&[0u8; 48]);

                self.0.update(&data[poff..][..256]);
            }
        }
    }

    // Produces MRENCLAVE value (SHA256 of fields specified in
    // https://github.com/enarx/enarx/wiki/SGX-Measurement)
    pub fn finish(self) -> Result<[u8; 32]> {
        Ok(self.0.finish())
    }
}

#[cfg(test)]
mod test {
    // TODO: Add tests (ex. for modulus, exponent of rsa key)
}
