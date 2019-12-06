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
use std::marker::PhantomData;

use bitflags::bitflags;
use sgx_types::secinfo::{Flags as Permissions, SecInfo};
use sgx_types::{secs::Secs, sigstruct::SigStruct, tcs::Tcs};

/// An offset reference with neither read nor write capabilities
///
/// The Handle struct allows the creation of an opaque reference to a
/// type that cannot be read or written. Neither the lifetime nor the
/// type are discarded. This allows us to refer to an offset inside
/// an enclave without fear that it will be dereferenced. The size of
/// the Handle is always 64 bits with natural alignment. Therefore,
/// the handle type can be embedded in structs.
#[repr(transparent)]
#[derive(Debug)]
pub struct Handle<'h, T>(u64, PhantomData<&'h T>);

impl<'h, T> Handle<'h, T> {
    pub unsafe fn new(ptr: usize) -> Self {
        Handle(ptr as u64, PhantomData)
    }
}

bitflags! {
    pub struct Flags: u64 {
        const MEASURE = 1 << 0;
    }
}

pub trait Enclave<'e> {
    fn enter(&self, handle: &mut Handle<'e, Tcs>) -> Result<()>;
}

pub trait Builder<'b>: Sized {
    type Enclave: Enclave<'b>;

    fn new(secs: Secs) -> Result<Self>;

    fn add_tcs(&mut self, tcs: Tcs, offset: usize) -> Result<Handle<'b, Tcs>>;

    fn add_struct<T>(
        &mut self,
        data: T,
        offset: usize,
        perms: Permissions,
    ) -> Result<Handle<'b, T>>;

    fn add_slice(
        &mut self,
        data: &[u8],
        offset: usize,
        flags: Flags,
        secinfo: SecInfo,
    ) -> Result<Handle<'b, ()>>;

    fn build(self, ss: SigStruct) -> Result<Self::Enclave>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align() {
        use std::mem::align_of;
        assert_eq!(align_of::<Handle<u32>>(), align_of::<u64>());
    }

    #[test]
    fn size() {
        use std::mem::size_of;
        assert_eq!(size_of::<Handle<u32>>(), size_of::<u64>());
    }
}
