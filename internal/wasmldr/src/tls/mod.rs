// SPDX-License-Identifier: Apache-2.0

//! TLS communication utilities.

use core::ops::Deref;
use std::error::Error;

use reqwest::tls;
use rustls::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use rustls::kx_group::{SECP256R1, SECP384R1, X25519};
use rustls::version::TLS13;
use rustls::{Certificate, PrivateKey, RootCertStore};

pub struct ClientConfig {
    pub root_certificates: RootCertStore,
    pub certificate_chain: Vec<Certificate>,
    pub certificate_key_der: PrivateKey,
}

pub struct Client(reqwest::blocking::Client);

impl Deref for Client {
    type Target = reqwest::blocking::Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Client {
    pub fn new(conf: ClientConfig) -> Result<Self, Box<dyn Error>> {
        let tls_config = rustls::ClientConfig::builder()
            .with_cipher_suites(&[
                TLS13_AES_256_GCM_SHA384,
                TLS13_AES_128_GCM_SHA256,
                TLS13_CHACHA20_POLY1305_SHA256,
            ])
            .with_kx_groups(&[&X25519, &SECP384R1, &SECP256R1])
            .with_protocol_versions(&[&TLS13])?
            .with_root_certificates(conf.root_certificates)
            .with_single_cert(conf.certificate_chain, conf.certificate_key_der)?;

        let client = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(tls_config)
            .https_only(true)
            .tls_built_in_root_certs(false)
            .min_tls_version(tls::Version::TLS_1_3)
            .build()?;

        Ok(Self(client))
    }
}

#[cfg(test)]
mod tests {
    use rustls_pemfile::{certs, pkcs8_private_keys, read_all, Item};

    use super::*;

    #[test]
    fn tls_config() {
        let mut root_certificates = rustls::RootCertStore::empty();
        assert_eq!(
            root_certificates.add_parsable_certificates(
                &certs(&mut include_bytes!("testdata/ca.crt").as_ref()).unwrap()
            ),
            (1, 0)
        );

        let certificate_chain = certs(&mut include_bytes!("testdata/client.crt").as_ref())
            .unwrap()
            .into_iter()
            .map(Certificate)
            .collect();

        let certificate_key_der = PrivateKey(
            pkcs8_private_keys(&mut include_bytes!("testdata/client.key").as_ref())
                .unwrap()
                .remove(0),
        );

        let client = Client::new(ClientConfig {
            root_certificates,
            certificate_chain,
            certificate_key_der,
        })
        .unwrap();

        // TODO: Start a TLS server in a separate thread, send a request from client and validate
        // TLS configuration used.
    }
}
