// SPDX-License-Identifier: Apache-2.0

//! Functionality for establishing keep identity.

mod pki;
mod platform;

use pki::PrivateKeyInfoExt;
use platform::{Platform, Technology};
use std::str::FromStr;

use std::time::Duration;

use anyhow::{bail, Context};
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_CLIENT_AUTH,
    ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};
use const_oid::AssociatedOid;
use getrandom::getrandom;
use pkcs8::der::asn1::{BitString, OctetString};
use pkcs8::der::referenced::{OwnedToRef, RefToOwned};
use pkcs8::der::Any;
use pkcs8::PrivateKeyInfo;
use sha2::{Digest, Sha256, Sha384};
use url::Url;
use wiggle::tracing::instrument;
use x509_cert::attr::Attribute;
use x509_cert::der::asn1::BitStringRef;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::ext::Extension;
use x509_cert::name::RdnSequence;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::{Certificate, PkiPath, TbsCertificate};
use zeroize::Zeroizing;

fn csr(pki: &PrivateKeyInfo<'_>, exts: Vec<Extension>) -> anyhow::Result<Vec<u8>> {
    // Request the extensions.
    let req = ExtensionReq::from(exts)
        .to_der()
        .context("failed to encode an extension request")?;

    // Embed the extension requests in an attribute.
    let any = Any::from_der(&req).context("failed to parse extension request from DER")?;
    let att_values = vec![any]
        .try_into()
        .context("failed to generate attribute values")?;
    let att = Attribute {
        oid: ExtensionReq::OID,
        values: att_values,
    };

    let attributes = vec![att]
        .try_into()
        .context("failed to generate CRI attributes")?;
    let public_key = pki.public_key().context("failed to extract public key")?;

    // Create a certification request information structure.
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        attributes,
        subject: RdnSequence::default(),
        public_key: public_key.ref_to_owned(),
    };

    let algorithm = pki
        .signs_with()
        .context("failed to query signing algorithm")?;
    let info_bytes = info.to_der().context("failed to encode CRI")?;

    // Sign the request.
    let sig = pki
        .sign(&info_bytes, algorithm)
        .context("failed to sign request")?;
    let signature = BitStringRef::from_bytes(sig.as_ref()).context("failed to parse signature")?;
    CertReq {
        info,
        algorithm: algorithm.ref_to_owned(),
        signature: signature.ref_to_owned(),
    }
    .to_der()
    .context("failed to encode CSR")
}

/// Generates a new private key and corresponding CSR
#[instrument]
pub fn generate() -> anyhow::Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let platform = Platform::get().context("failed to query platform")?;
    let cert_algo = match platform.technology() {
        Technology::Snp => SECP_384_R_1,
        Technology::Sgx => SECP_256_R_1,
        Technology::Kvm => SECP_256_R_1,
    };

    // Generate a keypair.
    let raw = PrivateKeyInfo::generate(cert_algo).context("failed to generate a private key")?;
    let pki = PrivateKeyInfo::from_der(raw.as_ref())
        .context("failed to parse DER-encoded private key")?;
    let der = pki
        .public_key()
        .context("failed to get public key")?
        .to_der()
        .context("failed to get der-encoded public key")?;

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

    let attestation_report = platform.attest(&key_hash).context("failed to attest")?;

    // Create extensions.
    let ext = vec![Extension {
        extn_id: platform.technology().into(),
        critical: false,
        extn_value: OctetString::new(attestation_report)
            .context("failed to wrap attestation evidence in `OctetString`")?,
    }];

    // Make a certificate signing request.
    let req = csr(&pki, ext).context("failed to generate a CSR")?;

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
    path.iter().rev().map(|c| Ok(c.to_der()?)).collect()
}

#[instrument(skip(key))]
pub fn selfsigned(key: impl AsRef<[u8]>) -> anyhow::Result<Vec<Vec<u8>>> {
    let pki = PrivateKeyInfo::from_der(key.as_ref())?;

    // Create a relative distinguished name.
    let rdns = RdnSequence::from_str("CN=localhost")?;

    // Create the extensions.
    let ku = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment).to_der()?;
    let eu = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH, ID_KP_CLIENT_AUTH]).to_der()?;
    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    }
    .to_der()?;

    // Steward uses UUIDs as serial numbers, use 16-octet long serial number to loosely
    // resemble format used by the Steward.
    let mut serial = [0u8; 16];
    getrandom(&mut serial)?;

    // Create the certificate body.
    let tbs = TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: SerialNumber::new(&serial)?,
        signature: pki.signs_with()?.ref_to_owned(),
        issuer: rdns.clone(),
        validity: Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365))?,
        subject: rdns,
        subject_public_key_info: pki.public_key()?.ref_to_owned(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            x509_cert::ext::Extension {
                extn_id: ID_CE_KEY_USAGE,
                critical: true,
                extn_value: OctetString::new(ku)?,
            },
            x509_cert::ext::Extension {
                extn_id: ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: OctetString::new(bc)?,
            },
            x509_cert::ext::Extension {
                extn_id: ID_CE_EXT_KEY_USAGE,
                critical: false,
                extn_value: OctetString::new(eu)?,
            },
        ]),
    };

    // Self-sign the certificate.
    let alg = tbs.signature.clone();
    let tbs_copy = tbs.clone();
    let sig = pki.sign(&tbs_copy.to_der()?, alg.owned_to_ref())?;
    let crt = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(&sig)?,
    };

    Ok(vec![crt.to_der()?])
}
