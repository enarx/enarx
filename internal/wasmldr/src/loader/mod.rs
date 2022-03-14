// SPDX-License-Identifier: Apache-2.0

mod acquired;
mod attested;
mod compiled;
mod configured;
mod connected;
mod pki;
mod requested;

use std::sync::Arc;

use rustls::{ClientConfig, ServerConfig};
use wasi_common::WasiCtx;
use wasmtime::{Linker, Store, Val};
use zeroize::Zeroizing;

use crate::config::Config;

pub struct Configured {
    config: Config,
}

pub struct Requested {
    config: Config,
    prvkey: Zeroizing<Vec<u8>>,
    crtreq: Vec<u8>,
}

pub struct Attested {
    config: Config,
    srvcfg: Arc<ServerConfig>,
    cltcfg: Arc<ClientConfig>,
}

pub struct Acquired {
    config: Config,
    srvcfg: Arc<ServerConfig>,
    cltcfg: Arc<ClientConfig>,

    webasm: Vec<u8>,
}

pub struct Compiled {
    config: Config,
    srvcfg: Arc<ServerConfig>,
    cltcfg: Arc<ClientConfig>,

    wstore: Store<WasiCtx>,
    linker: Linker<WasiCtx>,
}

pub struct Connected {
    wstore: Store<WasiCtx>,
    linker: Linker<WasiCtx>,
}

pub struct Completed {
    values: Vec<Val>,
}

pub struct Loader<T>(T);

impl Loader<Acquired> {
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

        let acquired = Self(Acquired {
            config: Config::default(),
            srvcfg: Arc::new(srvcfg),
            cltcfg: Arc::new(cltcfg),
            webasm: module.to_vec(),
        });

        let compiled = acquired.next()?;
        let connected = compiled.next()?;
        let completed = connected.next()?;
        Ok(completed.into())
    }
}

impl From<Config> for Loader<Configured> {
    fn from(config: Config) -> Self {
        Self(Configured { config })
    }
}

impl From<Loader<Completed>> for Vec<Val> {
    fn from(value: Loader<Completed>) -> Self {
        value.0.values
    }
}
