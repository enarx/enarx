// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

mod platform;

#[allow(unused_imports)]
use platform::{Platform, Technology};

use super::{pki::PrivateKeyInfoExt, Configured, Loader, Requested};

use anyhow::Result;
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};
use const_oid::AssociatedOid;
use pkcs8::PrivateKeyInfo;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::attr::Attribute;
use x509_cert::der::asn1::BitStringRef;
use x509_cert::der::{AnyRef, Decode, Encode};
use x509_cert::ext::Extension;
use x509_cert::name::RdnSequence;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq};

impl Loader<Configured> {
    pub fn make_csr(pki: &PrivateKeyInfo<'_>, exts: Vec<Extension<'_>>) -> Result<Vec<u8>> {
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

    pub fn next(self) -> Result<Loader<Requested>> {
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
        let req = Self::make_csr(&pki, ext)?;

        Ok(Loader(Requested {
            package: self.0.args.package,
            prvkey: raw,
            crtreq: req,
        }))
    }
}
