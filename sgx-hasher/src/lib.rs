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

use std::fs::File;
use std::io::Result;
use std::marker::PhantomData;
use std::mem::size_of_val;
use std::slice::from_raw_parts;
use openssl::{pkey::{Private, Public}, rsa::Rsa};
use hex;

use sgx_traits::{Hasher as HasherTrait, Enclave as EnclaveTrait, Flags};
use sgx_types::page::{Class as PageClass, Flags as PageFlags, SecInfo};
use sgx_types::secs::Secs;
use sgx_types::sig::{RsaExponent, RsaNumber};
use sgx_types::tcs::Tcs;
use sgx_types::Offset;
use sgx_sys::ioctl::*;

pub struct Hasher<'b> {
    rsa: Rsa<Private>, 
    file: File, 
    phantom: PhantomData<&'b ()>
}

impl<'b> HasherTrait<'b> for Hasher<'b> {
    type Enclave = Enclave<'b>;

    // Mimics call to SGX_IOC_ENCLAVE_CREATE (ECREATE)
    fn new(secs: Secs) -> Result<Self> {
        let _create = sgx::Create::new(&secs);
        let file = File::open("/dev/sgx/enclave")?;
        
        // From Rust OpenSSL: The public exponent will be 65537.
        let rsa = Rsa::generate(3072)?;

        Ok(Self{
            rsa: rsa, 
            file: file, 
            phantom: PhantomData
        })
    }

    fn get_mod(&self) -> RsaNumber {
        let mut rsanum = [0; 384];
        let modl = self.rsa.n().to_vec();
        rsanum.copy_from_slice(&modl);
        RsaNumber::new(rsanum)
    }

    fn get_exp(&self) -> RsaExponent {
        let exp_hex = hex::encode(self.rsa.e().to_vec());
        let exp_dec = u32::from_str_radix(&exp_hex[..], 16).unwrap();
        RsaExponent::new(exp_dec)
    }

    // TODO: make sure signature exists for this
    fn get_q1(&self) -> RsaNumber {
        // TODO: q1 = floor(signature.pow(2) / modulus)
        RsaNumber::default()
    }

    // TODO: make sure signature exists for this
    fn get_q2(&self) -> RsaNumber {
        // TODO: q2 = floor((signature.pow(3) - q1 * signature * modulus) / modulus)
        RsaNumber::default()
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

    // Mimics call to SGX_IOC_ENCLAVE_ADD_PAGES (EADD)
    unsafe fn add_slice(
        &mut self,
        data: &[u8],
        offset: usize,
        flags: Flags,
        secinfo: SecInfo,
    ) -> Result<Offset<[u8]>> {
        let _addpages = sgx::AddPages::new(data, offset, &secinfo, flags);
        Ok(offset.into())
    }

    // Mimics call to SGX_IOC_ENCLAVE_INIT (EINIT)
    fn hash(&self) -> Result<[u8; 32]> {
        // TODO: implement hash
        Ok([0u8; 32])
    }

    fn sign(&self) -> Result<()> {
        // TODO: implement signature on hash
        Ok(())
    }
}

pub struct Enclave<'e>(File, PhantomData<&'e ()>);

impl<'e> EnclaveTrait<'e> for Enclave<'e> {
    unsafe fn enter(&self, _: &mut Offset<Tcs>) -> Result<()> {
        Err(std::io::ErrorKind::Other.into())
    }
}

#[cfg(test)]
mod test {
    // TODO: Add tests (ex. for modulus, exponent of rsa key)
}
