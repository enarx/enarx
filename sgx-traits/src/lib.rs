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
use sgx_types::page::{Flags as PageFlags, SecInfo};
use sgx_types::{secs::Secs, sig::Signature, tcs::Tcs, Offset};

bitflags! {
    pub struct Flags: u64 {
        const MEASURE = 1 << 0;
    }
}

pub trait Enclave<'e> {
    fn enter(&self, offset: &mut Offset<'e, Tcs>) -> Result<()>;
}

pub trait Builder<'b>: Sized {
    type Enclave: Enclave<'b>;

    fn new(secs: Secs) -> Result<Self>;

    fn add_tcs(&mut self, tcs: Tcs, offset: usize) -> Result<Offset<'b, Tcs>>;

    fn add_struct<T>(&mut self, data: T, offset: usize, flags: PageFlags) -> Result<Offset<'b, T>>;

    fn add_slice(
        &mut self,
        data: &[u8],
        offset: usize,
        flags: Flags,
        secinfo: SecInfo,
    ) -> Result<Offset<'b, ()>>;

    fn build(self, sig: Signature) -> Result<Self::Enclave>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align() {
        use std::mem::align_of;
        assert_eq!(align_of::<Offset<u32>>(), align_of::<u64>());
    }

    #[test]
    fn size() {
        use std::mem::size_of;
        assert_eq!(size_of::<Offset<u32>>(), size_of::<u64>());
    }
}
