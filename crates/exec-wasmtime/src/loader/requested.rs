// SPDX-License-Identifier: Apache-2.0

use super::super::{Package, PACKAGE_CONFIG, PACKAGE_ENTRYPOINT};
use super::pki::PrivateKeyInfoExt;
use super::{Attested, Loader, Requested};

use std::io::Read;
use std::ops::Deref;

#[cfg(unix)]
use std::os::unix::prelude::FromRawFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_CLIENT_AUTH,
    ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};
use drawbridge_client::types::{Meta, TagEntry, TreeDirectory, TreeEntry, TreePath};
use drawbridge_client::{scope, Client, Entity, Node, Scope};
use enarx_config::Config;
use getrandom::getrandom;
use pkcs8::PrivateKeyInfo;
use rustls::{cipher_suite::*, kx_group::*, version::TLS13, *};
use ureq::serde_json;
use url::Url;
use wasi_crypto::AlgorithmType;
use x509_cert::der::asn1::{BitStringRef, UIntRef};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::RdnSequence;
use x509_cert::time::Validity;
use x509_cert::{Certificate, PkiPath, TbsCertificate};

/// Maximum size of WASM module in bytes
const MAX_WASM_SIZE: u64 = 100_000_000;
/// Maximum size of Enarx.toml in bytes
const MAX_CONF_SIZE: u64 = 1_000_000;
/// Maximum directory size in bytes
const MAX_DIR_SIZE: u64 = 1_000_000;

/// Maximum size of top-level response body in bytes
const MAX_TOP_SIZE: u64 = MAX_WASM_SIZE;

const TOML_MEDIA_TYPE: &str = "application/toml";
const WASM_MEDIA_TYPE: &str = "application/wasm";

fn get_wasm(root: Entity<'_, impl Scope, scope::Node>, entry: &TreeEntry) -> Result<Vec<u8>> {
    ensure!(
        entry.meta.mime.essence_str() == WASM_MEDIA_TYPE,
        "invalid `{}` media type `{}`",
        *PACKAGE_ENTRYPOINT,
        entry.meta.mime.essence_str()
    );
    let (meta, wasm) = Node::new(root, &PACKAGE_ENTRYPOINT.clone().into())
        .get_bytes(MAX_WASM_SIZE)
        .with_context(|| format!("failed to fetch `{}`", *PACKAGE_ENTRYPOINT))?;
    ensure!(
        meta == entry.meta,
        "`{}` metadata does not match directory entry metadata",
        *PACKAGE_ENTRYPOINT,
    );
    Ok(wasm)
}

fn get_package(
    root: Entity<'_, impl Scope, scope::Node>,
    dir: TreeDirectory,
) -> Result<(Vec<u8>, Option<String>)> {
    let wasm = dir
        .get(&PACKAGE_ENTRYPOINT)
        .ok_or_else(|| anyhow!("directory does not contain `{}`", *PACKAGE_ENTRYPOINT))
        .and_then(|e| get_wasm(root.clone(), e).context("failed to get Wasm"))?;

    let entry = if let Some(entry) = dir.get(&PACKAGE_CONFIG) {
        entry
    } else {
        return Ok((wasm, None));
    };
    ensure!(
        entry.meta.mime.essence_str() == TOML_MEDIA_TYPE,
        "invalid `{}` media type `{}`",
        *PACKAGE_CONFIG,
        entry.meta.mime.essence_str()
    );
    let (meta, conf) = Node::new(root, &PACKAGE_CONFIG.clone().into())
        .get_string(MAX_CONF_SIZE)
        .with_context(|| format!("failed to fetch `{}`", *PACKAGE_CONFIG))?;
    ensure!(
        meta == entry.meta,
        "`{}` metadata does not match directory entry metadata",
        *PACKAGE_CONFIG,
    );

    Ok((wasm, Some(conf)))
}

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
        path.iter().rev().map(|c| Ok(c.to_vec()?)).collect()
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
        getrandom(&mut serial)?;

        // Create the certificate body.
        let tbs = TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: UIntRef::new(&serial)?,
            signature: pki.signs_with()?,
            issuer: RdnSequence::from_der(&rdns)?,
            validity: Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365))?,
            subject: RdnSequence::from_der(&rdns)?,
            subject_public_key_info: pki.public_key()?,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                x509_cert::ext::Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: &ku,
                },
                x509_cert::ext::Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: &bc,
                },
                x509_cert::ext::Extension {
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
            signature: BitStringRef::from_bytes(&sig)?,
        };

        Ok(vec![crt.to_vec()?])
    }

    pub fn next(mut self) -> Result<Loader<Attested>> {
        let (webasm, config) = match self.0.package {
            Package::Remote(ref url) => {
                let cl = Client::<scope::Unknown>::new_scoped(url.clone())
                    .context("failed to construct client")?;
                let top = Entity::new(&cl);
                let (Meta { size, mime, .. }, mut rdr) = top
                    .get(MAX_TOP_SIZE)
                    .with_context(|| format!("failed to fetch top-level URL `{url}`"))?;
                match mime.essence_str() {
                    WASM_MEDIA_TYPE => {
                        ensure!(
                            size <= MAX_WASM_SIZE,
                            "Wasm size of `{size}` exceeds the limit of `{MAX_WASM_SIZE}`"
                        );
                        let size = size
                            .try_into()
                            .with_context(|| format!("failed to convert `{size}` to usize"))?;
                        let mut wasm = Vec::with_capacity(size);
                        let n = rdr
                            .read_to_end(&mut wasm)
                            .context("failed to fetch workload")?;
                        ensure!(n == size, "invalid amount of Wasm bytes fetched");
                        (wasm, None)
                    }
                    TreeDirectory::<()>::TYPE => serde_json::from_reader(rdr)
                        .context("failed to decode response body")
                        .and_then(|dir| {
                            get_package(top.clone().scope(), dir).context("failed to fetch package")
                        })?,
                    typ => {
                        let tag = serde_json::from_reader(rdr).with_context(|| format!("failed to decode top-level entity of type `{typ}` as either Wasm module, Drawbridge directory or a tag"))?;
                        let entry: TreeEntry = match tag {
                            TagEntry::Unsigned(e) => e,
                            TagEntry::Signed(_jws) => {
                                // TODO: Support signed tags
                                bail!("signed tags are not currently supported")
                            }
                        };
                        let tree = top.child("tree");
                        let root = Node::new(tree.clone(), &TreePath::ROOT);
                        match entry.meta.mime.essence_str() {
                            WASM_MEDIA_TYPE => get_wasm(tree, &entry)
                                .map(|wasm| (wasm, None))
                                .context("failed to fetch workload")?,
                            TreeDirectory::<()>::TYPE => {
                                let (meta, dir) = root
                                    .get_json::<TreeDirectory>(MAX_DIR_SIZE)
                                    .context("failed to get root directory")?;
                                ensure!(
                                    meta == entry.meta,
                                    "directory metadata does not match tag entry metadata"
                                );
                                get_package(tree, dir).context("failed to fetch package")?
                            }
                            typ => bail!("unsupported root type `{typ}`"),
                        }
                    }
                }
            }
            Package::Local {
                ref mut wasm,
                ref mut conf,
            } => {
                let mut webasm = Vec::new();
                // SAFETY: This FD was passed to us by the host and we trust that we have exclusive
                // access to it.
                #[cfg(unix)]
                let mut wasm = unsafe { std::fs::File::from_raw_fd(*wasm) };

                wasm.read_to_end(&mut webasm)
                    .context("failed to read WASM module")?;

                let config = if let Some(conf) = conf.as_mut() {
                    let mut config = String::new();
                    // SAFETY: This FD was passed to us by the host and we trust that we have exclusive
                    // access to it.
                    #[cfg(unix)]
                    let mut conf = unsafe { std::fs::File::from_raw_fd(*conf) };

                    conf.read_to_string(&mut config)
                        .context("failed to read config")?;

                    Some(config)
                } else {
                    None
                };
                (webasm, config)
            }
        };
        let config: Config = if let Some(ref config) = config {
            toml::from_str(config).context("failed to parse config")?
        } else {
            Default::default()
        };

        // If specified in the config
        let certs = match config.steward.as_ref() {
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

        // Setup Wasi-Crypto
        let pki = PrivateKeyInfo::from_der(&self.0.prvkey)?;
        let algo_str = match pki.algorithm.oid {
            SECP_384_R_1=> "ECDSA_P384_SHA384",
            SECP_256_R_1=> "ECDSA_P256_SHA256",
            _ => return Err(anyhow!("Unknown algorithm"))
        };

        let wasi_crypto_ctx = wasmtime_wasi_crypto::WasiCryptoCtx::new();
        wasi_crypto_ctx.keypair_import(AlgorithmType::Signatures, algo_str, blah, wasi_crypto::KeyPairEncoding::Raw);

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
            srvcfg: Arc::new(srvcfg),
            cltcfg: Arc::new(cltcfg),
            config,
            webasm,
        }))
    }
}
