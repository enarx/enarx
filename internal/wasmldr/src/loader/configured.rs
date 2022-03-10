// SPDX-License-Identifier: Apache-2.0

use super::{Configured, Loader, Requested};

use anyhow::Result;
use const_oid::ObjectIdentifier;

use const_oid::db::rfc5912::ECDSA_WITH_SHA_256;
use const_oid::AssociatedOid;
use pkcs8::{AlgorithmIdentifier, PrivateKeyInfo, SubjectPublicKeyInfo};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
use sec1::EcPrivateKey;
use x509::der::{asn1::BitString, Any, Decodable, Encodable};
use x509::request::{CertReq, CertReqInfo, ExtensionReq};
use x509::{attr::Attribute, ext::Extension, name::RdnSequence};

impl Loader<Configured> {
    const KVM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.1");
    //const SGX: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    //const SNP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.3");

    pub fn next(self) -> Result<Loader<Requested>> {
        // TODO:
        //   1. get attestation
        //   2. get intermediate cert
        //   3. choose key type based on technology
        //   4. generate tech-specific attestation extension request

        // Generate a keypair.
        let rng = ring::rand::SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ALG, &rng)?;
        let pki = PrivateKeyInfo::from_der(doc.as_ref())?;
        let spki = SubjectPublicKeyInfo {
            algorithm: pki.algorithm,
            subject_public_key: EcPrivateKey::from_der(pki.private_key)?.public_key.unwrap(),
        };

        // Request the extensions.
        let req = ExtensionReq::from(vec![Extension {
            extn_id: Self::KVM,
            critical: false,
            extn_value: &[],
        }])
        .to_vec()?;

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
            public_key: spki,
        };

        // Sign the request.
        let kp = EcdsaKeyPair::from_pkcs8(&ALG, doc.as_ref())?;
        let sig = kp.sign(&rng, &cri.to_vec()?)?;
        let req = CertReq {
            info: cri,
            algorithm: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: BitString::from_bytes(sig.as_ref())?,
        };

        Ok(Loader(Requested {
            config: self.0.config,
            prvkey: doc.as_ref().to_vec().into(),
            crtreq: req.to_vec()?,
        }))
    }
}
