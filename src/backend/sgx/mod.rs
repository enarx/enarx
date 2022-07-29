// SPDX-License-Identifier: Apache-2.0

mod attestation;
mod builder;
mod config;
mod data;
mod hasher;
mod ioctls;
mod thread;

use super::Loader;

use anyhow::Result;
use mmarinus::{perms, Map};

use crate::backend::Signatures;
use std::arch::x86_64::__cpuid_count;
use std::fs::File;
use std::sync::{Arc, RwLock};

pub const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

struct Tcs;

struct Keep {
    sallyport_block_size: u64,
    mem: Map<perms::Unknown>,
    tcs: RwLock<Vec<*const Tcs>>,
    enclave: File,
}

pub struct Backend;

impl crate::backend::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "sgx"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        include_bytes!(env!("CARGO_BIN_FILE_ENARX_SHIM_SGX"))
    }

    #[inline]
    fn have(&self) -> bool {
        self.data().iter().all(|x| x.pass)
    }

    fn data(&self) -> Vec<super::Datum> {
        let mut data = vec![data::dev_sgx_enclave()];

        data.extend(data::CPUIDS.iter().map(|c| c.into()));

        let max = unsafe { __cpuid_count(0x00000000, 0x00000000) }.eax;
        data.push(data::epc_size(max));

        data
    }

    fn config(&self) -> Vec<super::Datum> {
        vec![data::aesm_socket()]
    }

    #[inline]
    fn keep(
        &self,
        shim: &[u8],
        exec: &[u8],
        signatures: Option<Signatures>,
    ) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec, signatures)
    }

    #[inline]
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>> {
        hasher::Hasher::load(shim, exec, None)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(debug_assertions, ignore = "debug_assertions active")]
    fn shim_sgx_binary_size() {
        use crate::backend::Backend;

        let max_shim_size = 500_000;
        let shim = super::Backend.shim();
        if shim.len() > max_shim_size {
            panic!(
                "shim size should be less than {} bytes, but is {} bytes",
                max_shim_size,
                shim.len()
            );
        }
    }
}
