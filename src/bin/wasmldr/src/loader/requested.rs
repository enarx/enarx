// SPDX-License-Identifier: Apache-2.0

use super::{pki::PrivateKeyInfoExt, Attested, Loader, Requested};

use std::time::Duration;
use std::{io::Read, ops::Deref, sync::Arc};

use anyhow::{anyhow, Result};

use pkcs8::PrivateKeyInfo;
use rustls::{cipher_suite::*, kx_group::*, version::TLS13, *};
use url::Url;
use x509::der::asn1::{BitString, UIntBytes};
use x509::der::{Decodable, Encodable};
use x509::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509::name::RdnSequence;
use x509::time::Validity;
use x509::{Certificate, PkiPath, TbsCertificate};

use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_CLIENT_AUTH,
    ID_KP_SERVER_AUTH,
};
use rustix::rand;

impl Loader<Requested> {
    fn steward(&self, url: &Url) -> Result<Vec<Vec<u8>>> {
        if url.scheme() != "https" {
            return Err(anyhow!("refusing to use an unencrypted steward url"));
        }

        // Send the attestation to the steward.
        let response = ureq::post(url.as_str())
            .set("Content-Type", "application/pkcs10")
            .send_bytes(&self.0.crtreq)?;

        // Read the result.
        let mut body = Vec::new();
        response.into_reader().read_to_end(&mut body)?;

        // Decode the certificate chain.
        let path = PkiPath::from_der(&body)?;
        path.0.iter().rev().map(|c| Ok(c.to_vec()?)).collect()
    }

    fn selfsigned(&self) -> Result<Vec<Vec<u8>>> {
        let pki = PrivateKeyInfo::from_der(&self.0.prvkey)?;

        // Create a relative distinguished name.
        let rdns = RdnSequence::encode_from_string("CN=localhost")?;

        // Create the extensions.
        let ku = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment).to_vec()?;
        let eu = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH, ID_KP_CLIENT_AUTH]).to_vec()?;
        let bc = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_vec()?;

        let mut serial: [u8; 32] = [0u8; 32];
        rand::getrandom(&mut serial, rand::GetRandomFlags::RANDOM)?;

        // Create the certificate body.
        let tbs = TbsCertificate {
            version: x509::Version::V3,
            serial_number: UIntBytes::new(&serial)?,
            signature: pki.signs_with()?,
            issuer: RdnSequence::from_der(&rdns)?,
            validity: Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365))?,
            subject: RdnSequence::from_der(&rdns)?,
            subject_public_key_info: pki.public_key()?,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                x509::ext::Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: &ku,
                },
                x509::ext::Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: &bc,
                },
                x509::ext::Extension {
                    extn_id: ID_CE_EXT_KEY_USAGE,
                    critical: false,
                    extn_value: &eu,
                },
            ]),
        };

        // Self-sign the certificate.
        let alg = tbs.signature;
        let sig = pki.sign(&tbs.to_vec()?, alg)?;
        let crt = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature: BitString::from_bytes(&sig)?,
        };

        Ok(vec![crt.to_vec()?])
    }

    pub fn next(self) -> Result<Loader<Attested>> {
        // If the user supplied
        let certs = match self.0.config.steward.as_ref() {
            Some(url) => self.steward(url)?,
            None => self.selfsigned()?,
        }
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();

        // TODO: load this policy from `Config`.
        // https://github.com/enarx/enarx/issues/1548
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
            .with_no_client_auth() // TODO: https://github.com/enarx/enarx/issues/1547
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
