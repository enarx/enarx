// SPDX-License-Identifier: Apache-2.0

//! Functionality for establishing keep identity.

mod pki;
mod platform;

use pki::PrivateKeyInfoExt;
use platform::{Platform, Technology};
use tracing::instrument;

use std::time::Duration;

use anyhow::bail;
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_CLIENT_AUTH,
    ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};
use const_oid::AssociatedOid;
use getrandom::getrandom;
use pkcs8::PrivateKeyInfo;
use sha2::{Digest, Sha256, Sha384};
use url::Url;
use x509_cert::attr::Attribute;
use x509_cert::der::asn1::{BitStringRef, UIntRef};
use x509_cert::der::{AnyRef, Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::ext::Extension;
use x509_cert::name::RdnSequence;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq};
use x509_cert::time::Validity;
use x509_cert::{Certificate, PkiPath, TbsCertificate};
use zeroize::Zeroizing;

fn csr(pki: &PrivateKeyInfo<'_>, exts: Vec<Extension<'_>>) -> anyhow::Result<Vec<u8>> {
    // Request the extensions.
    let req = ExtensionReq::from(exts).to_vec()?;

    // Embed the extension requests in an attribute.
    let any = AnyRef::from_der(&req)?;
    let att = Attribute {
        oid: ExtensionReq::OID,
        values: vec![any].try_into()?,
    };

    // Create a certification request information structure.
    let cri = CertReqInfo {
        version: x509_cert::request::Version::V1,
        attributes: vec![att].try_into()?,
        subject: RdnSequence::default(),
        public_key: pki.public_key()?,
    };

    // Sign the request.
    let sig = pki.sign(&cri.to_vec()?, pki.signs_with()?)?;
    let req = CertReq {
        info: cri,
        algorithm: pki.signs_with()?,
        signature: BitStringRef::from_bytes(sig.as_ref())?,
    };

    Ok(req.to_vec()?)
}

/// Generates a new private key and corresponding CSR
#[instrument]
pub fn generate() -> anyhow::Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let platform = Platform::get()?;
    let cert_algo = match platform.technology() {
        Technology::Snp => SECP_384_R_1,
        Technology::Sgx => SECP_256_R_1,
        Technology::Kvm => SECP_256_R_1,
    };

    // Generate a keypair.
    let raw = PrivateKeyInfo::generate(cert_algo)?;
    let pki = PrivateKeyInfo::from_der(raw.as_ref())?;
    let der = pki.public_key().unwrap().to_vec().unwrap();

    let mut key_hash = [0u8; 64];
    match platform.technology() {
        Technology::Snp => {
            let hash = Sha384::digest(der);
            key_hash[..48].copy_from_slice(&hash);
        }
        _ => {
            let hash = Sha256::digest(der);
            key_hash[..32].copy_from_slice(&hash);
        }
    };

    let attestation_report = platform.attest(&key_hash)?;

    // Create extensions.
    let ext = vec![Extension {
        extn_id: platform.technology().into(),
        critical: false,
        extn_value: &attestation_report,
    }];

    // Make a certificate signing request.
    let req = csr(&pki, ext)?;

    Ok((raw, req))
}

#[instrument(skip(csr))]
pub fn steward(url: &Url, csr: impl AsRef<[u8]>) -> anyhow::Result<Vec<Vec<u8>>> {
    if url.scheme() != "https" {
        bail!("refusing to use an unencrypted steward url");
    }

    // Send the attestation to the steward.
    let response = ureq::post(url.as_str())
        .set("Content-Type", "application/pkcs10")
        .send_bytes(csr.as_ref())?;

    // Read the result.
    let mut body = Vec::new();
    response.into_reader().read_to_end(&mut body)?;

    // Decode the certificate chain.
    let path = PkiPath::from_der(&body)?;
    path.iter().rev().map(|c| Ok(c.to_vec()?)).collect()
}

#[instrument(skip(key))]
pub fn selfsigned(key: impl AsRef<[u8]>) -> anyhow::Result<Vec<Vec<u8>>> {
    let pki = PrivateKeyInfo::from_der(key.as_ref())?;

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

    // Steward uses UUIDs as serial numbers, use 16-octet long serial number to loosely
    // resemble format used by the Steward.
    let mut serial = [0u8; 16];
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
