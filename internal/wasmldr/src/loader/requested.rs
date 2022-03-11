// SPDX-License-Identifier: Apache-2.0

use super::{Attested, Loader, Requested};

use std::{io::Read, ops::Deref, sync::Arc};

use anyhow::{anyhow, Result};
use rustls::{cipher_suite::*, kx_group::*, version::TLS13, *};
use x509::der::{Decodable, Encodable};
use x509::PkiPath;

impl Loader<Requested> {
    const DEFAULT_STEWARD: &'static str = "https://steward-dev.onrender.com";

    pub fn next(self) -> Result<Loader<Attested>> {
        // Get the steward URL.
        let url = self
            .0
            .config
            .steward
            .as_ref()
            .map(|url| url.as_str())
            .unwrap_or(Self::DEFAULT_STEWARD);
        if !url.starts_with("https:") {
            return Err(anyhow!("refusing to use an unencrypted steward url"));
        }

        // Send the attestation to the steward.
        let response = ureq::post(url)
            .set("Content-Type", "application/pkcs10")
            .send_bytes(&self.0.crtreq)?;

        // Read the result.
        let mut body = Vec::new();
        response.into_reader().read_to_end(&mut body)?;

        // Decode the certificate chain.
        let path = PkiPath::from_der(&body)?;
        let certs = path
            .0
            .iter()
            .rev()
            .map(|c| Certificate(c.to_vec().unwrap()))
            .collect::<Vec<_>>();

        // TODO: load this policy from `Config`.
        let protocol_versions = &[&TLS13];
        let kx_groups = &[&X25519, &SECP384R1, &SECP256R1];
        let cipher_suites = &[
            TLS13_AES_256_GCM_SHA384,
            TLS13_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
        ];

        // Set up the server config.
        let srvcfg = ServerConfig::builder()
            .with_cipher_suites(cipher_suites)
            .with_kx_groups(kx_groups)
            .with_protocol_versions(protocol_versions)?
            .with_no_client_auth() // TODO: Enable client auth
            .with_single_cert(certs.clone(), PrivateKey(self.0.prvkey.deref().clone()))?;

        // Set up root store.
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        // Set up client config.
        let cltcfg = ClientConfig::builder()
            .with_cipher_suites(cipher_suites)
            .with_kx_groups(kx_groups)
            .with_protocol_versions(protocol_versions)?
            .with_root_certificates(root_store)
            .with_single_cert(certs, PrivateKey(self.0.prvkey.deref().clone()))?;

        Ok(Loader(Attested {
            config: self.0.config,
            srvcfg: Arc::new(srvcfg),
            cltcfg: Arc::new(cltcfg),
        }))
    }
}
