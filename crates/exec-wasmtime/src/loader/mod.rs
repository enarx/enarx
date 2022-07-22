// SPDX-License-Identifier: Apache-2.0
//! The Loader State Machine
//!
//! This file contains the `Loader` type which is a state machine for bringing
//! up a workload. Typically you would start by converting a `Config` into a
//! `Loader` and then just iterating through the states. However, there is also
//! a "short cut" `Loader::run()` function used for testing the late stages of
//! the bring up process.
//!
//! The types are defined in sequential order.

mod attested;
mod compiled;
mod configured;
mod connected;
mod pki;
mod requested;

use super::{Args, Package};

use std::sync::Arc;

use enarx_config::Config;
use rustls::{ClientConfig, ServerConfig};
use wasi_common::WasiCtx;
use wasmtime::{Linker, Store, Val};
use zeroize::Zeroizing;

/// The first state, indicating successful configuration
pub struct Configured {
    args: Args,
}

/// The second state, indicating that a CSR has been generated
pub struct Requested {
    package: Package,
    prvkey: Zeroizing<Vec<u8>>,
    crtreq: Vec<u8>,
}

/// The third state, indicating receipt of the configuration, certificate, WASM module and configuration
pub struct Attested {
    srvcfg: Arc<ServerConfig>,
    cltcfg: Arc<ClientConfig>,
    config: Config,
    webasm: Vec<u8>,
}

/// The fifth state, indicating compilation of the WASM module
pub struct Compiled {
    srvcfg: Arc<ServerConfig>,
    cltcfg: Arc<ClientConfig>,
    config: Config,
    wstore: Store<WasmContext>,
    linker: Linker<WasmContext>,
}

/// The sixth state, indicating connection of all sockets
pub struct Connected {
    wstore: Store<WasmContext>,
    linker: Linker<WasmContext>,
}

/// The final state, indicating completion of the workload
pub struct Completed {
    values: Vec<Val>,
}

/// The Wasmtime & Wasi-Crypto context
pub struct WasmContext {
    wasi: WasiCtx,
    wasi_crypto: wasmtime_wasi_crypto::WasiCryptoCtx,
}

pub struct Loader<T>(T);

impl Loader<Attested> {
    #[cfg(test)]
    pub fn run(module: &[u8]) -> anyhow::Result<Vec<Val>> {
        use rustls::{server::ResolvesServerCert, RootCertStore};

        struct Resolver;

        impl ResolvesServerCert for Resolver {
            fn resolve(
                &self,
                _client_hello: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                None
            }
        }

        let srvcfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver));

        let cltcfg = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();

        let attested = Self(Attested {
            srvcfg: Arc::new(srvcfg),
            cltcfg: Arc::new(cltcfg),
            config: Default::default(),
            webasm: module.to_vec(),
        });

        let compiled = attested.next()?;
        let connected = compiled.next()?;
        let completed = connected.next()?;
        Ok(completed.into())
    }
}

impl From<Args> for Loader<Configured> {
    fn from(args: Args) -> Self {
        Self(Configured { args })
    }
}

impl From<Loader<Completed>> for Vec<Val> {
    fn from(value: Loader<Completed>) -> Self {
        value.0.values
    }
}
