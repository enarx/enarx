// SPDX-License-Identifier: Apache-2.0

mod attestation;
mod builder;
mod config;
mod data;
mod enarxcall;
mod hasher;
mod ioctls;
mod thread;

use super::Loader;

use anyhow::{Context, Result};
use mmarinus::{perms, Map};

use crate::backend::Signatures;
use std::arch::x86_64::__cpuid_count;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use der::Sequence;
use x509_cert::Certificate;

pub const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";
pub const FMSPC_PATH: &str = "/var/cache/intel-sgx/fmspc.txt";
pub const TCB_PATH: &str = "/var/cache/intel-sgx/tcb.der";

pub type Tcs = usize;

#[derive(Sequence)]
pub(crate) struct TcbPackage<'a> {
    pub(crate) crts: Vec<Certificate<'a>>,
    #[asn1(type = "OCTET STRING")]
    pub(crate) report: &'a [u8],
}

pub(crate) struct Keep {
    sallyport_block_size: u64,
    mem: Map<perms::Unknown>,
    tcs: RwLock<Vec<Tcs>>,
    enclave: Mutex<File>,
}

impl Keep {
    fn push_tcs(&self, tcs: Tcs) {
        self.tcs.write().unwrap().push(tcs)
    }
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
        data.push(data::intel_crl());
        data.push(data::tcb_fmspc_cached());

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

/// Returns the "system-level" search path for the SGX
/// CRLs (`/var/cache/intel-sgx`).
pub fn sgx_cache_dir() -> anyhow::Result<PathBuf> {
    const CACHE_DIR: &str = "/var/cache";

    let mut sys = PathBuf::from(CACHE_DIR);
    if sys.exists() && sys.is_dir() {
        sys.push("intel-sgx");
        Ok(sys)
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
            .with_context(|| format!("Directory `{CACHE_DIR}` does not exist!"))
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
