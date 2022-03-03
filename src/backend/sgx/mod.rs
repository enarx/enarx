// SPDX-License-Identifier: Apache-2.0

mod attestation;
mod builder;
mod config;
mod data;
mod hasher;
mod ioctls;
mod thread;

use super::probe::common::system_info;
use super::Loader;

use anyhow::Result;
use mmarinus::{perms, Map};

use std::arch::x86_64::__cpuid_count;
use std::sync::{Arc, RwLock};

struct Tcs;

struct Keep {
    _mem: Map<perms::Unknown>,
    tcs: RwLock<Vec<*const Tcs>>,
}

pub struct Backend;

impl crate::backend::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "sgx"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sgx"))
    }

    #[inline]
    fn have(&self) -> bool {
        self.data().iter().all(|x| x.pass)
    }

    fn data(&self) -> Vec<super::Datum> {
        let mut data = vec![system_info(), data::dev_sgx_enclave()];

        data.extend(data::CPUIDS.iter().map(|c| c.into()));

        let max = unsafe { __cpuid_count(0x00000000, 0x00000000) }.eax;
        data.push(data::epc_size(max));

        data
    }

    #[inline]
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec)
    }

    #[inline]
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>> {
        hasher::Hasher::load(shim, exec)
    }
}
