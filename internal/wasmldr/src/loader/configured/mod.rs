// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

mod platform;

#[allow(unused_imports)]
use platform::{Platform, Technology};

use super::{pki::PrivateKeyInfoExt, Configured, Loader, Requested};

use anyhow::Result;

use const_oid::{db::rfc5912::SECP_256_R_1, AssociatedOid, ObjectIdentifier};
use pkcs8::PrivateKeyInfo;
use x509::der::{asn1::BitString, Any, Decodable, Encodable};
use x509::request::{CertReq, CertReqInfo, ExtensionReq};
use x509::{attr::Attribute, ext::Extension, name::RdnSequence};

impl Loader<Configured> {
    const KVM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.1");
    //const SGX: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    //const SNP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.3");

    pub fn make_csr(pki: &PrivateKeyInfo<'_>, exts: Vec<Extension<'_>>) -> Result<Vec<u8>> {
        // Request the extensions.
        let req = ExtensionReq::from(exts).to_vec()?;

        // Embed the extension requests in an attribute.
        let any = Any::from_der(&req)?;
        let att = Attribute {
            oid: ExtensionReq::OID,
            values: vec![any].try_into()?,
        };

        // Create a certification request information structure.
        let cri = CertReqInfo {
            version: x509::request::Version::V1,
            attributes: vec![att].try_into()?,
            subject: RdnSequence::default(),
            public_key: pki.public_key()?,
        };

        // Sign the request.
        let sig = pki.sign(&cri.to_vec()?, pki.signs_with()?)?;
        let req = CertReq {
            info: cri,
            algorithm: pki.signs_with()?,
            signature: BitString::from_bytes(sig.as_ref())?,
        };

        Ok(req.to_vec()?)
    }

    pub fn next(self) -> Result<Loader<Requested>> {
        // TODO:
        //   1. get attestation
        //   2. get intermediate cert
        //   3. choose key type based on technology
        //   4. generate tech-specific attestation extension request

        // Generate a keypair.
        let raw = PrivateKeyInfo::generate(SECP_256_R_1)?;
        let pki = PrivateKeyInfo::from_der(raw.as_ref())?;

        // Create extensions.
        let ext = vec![Extension {
            extn_id: Self::KVM,
            critical: false,
            extn_value: &[],
        }];

        // Make a certificate signing request.
        let req = Self::make_csr(&pki, ext)?;

        Ok(Loader(Requested {
            config: self.0.config,
            prvkey: raw,
            crtreq: req,
        }))
    }
}
