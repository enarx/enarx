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

use std::io::Result;

use bitflags::bitflags;
use sgx_types::{page, secs, sig};

bitflags! {
    pub struct Flags: u64 {
        const MEASURE = 1 << 0;
    }
}

pub trait Enclave {
    unsafe fn enter(&self, offset: usize) -> Result<()>;
}

pub trait Builder: Sized {
    type Enclave: Enclave;

    fn new(secs: secs::Secs) -> Result<Self>;

    unsafe fn add(
        &mut self,
        offset: usize,
        data: &[u8],
        flags: Flags,
        secinfo: page::SecInfo,
    ) -> Result<()>;

    fn build(self, sig: sig::Signature) -> Result<Self::Enclave>;
}
