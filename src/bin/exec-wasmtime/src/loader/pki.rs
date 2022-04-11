// SPDX-License-Identifier: Apache-2.0
//! Some cryptographic utilities

use anyhow::{anyhow, Result};
use pkcs8::{AlgorithmIdentifier, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfo};
use zeroize::Zeroizing;

use sec1::EcPrivateKey;
use x509::der::{Decodable, Encodable};

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY as ECPK, SECP_256_R_1 as P256,
    SECP_384_R_1 as P384,
};

const ES256: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_256,
    parameters: None,
};

const ES384: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_384,
    parameters: None,
};

pub trait PrivateKeyInfoExt {
    /// Generates a keypair
    ///
    /// Returns the DER encoding of the `PrivateKeyInfo` type.
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>>;

    /// Get the public key
    ///
    /// This function creates a `SubjectPublicKeyInfo` which corresponds with
    /// this private key. Note that this function does not do any cryptographic
    /// calculations. It expects that the `PrivateKeyInfo` already contains the
    /// public key.
    fn public_key(&self) -> Result<SubjectPublicKeyInfo<'_>>;

    /// Get the default signing algorithm for this `SubjectPublicKeyInfo`
    fn signs_with(&self) -> Result<AlgorithmIdentifier<'_>>;

    /// Signs the body with the specified algorithm
    ///
    /// Note that the signature is returned in its encoded form as it will
    /// appear in an X.509 certificate or PKCS#10 certification request.
    fn sign(&self, body: &[u8], algo: AlgorithmIdentifier<'_>) -> Result<Vec<u8>>;
}

impl<'a> PrivateKeyInfoExt for PrivateKeyInfo<'a> {
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>> {
        let rand = ring::rand::SystemRandom::new();

        let doc = match oid {
            P256 => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
                EcdsaKeyPair::generate_pkcs8(&ALG, &rand)?
            }

            P384 => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING as ALG};
                EcdsaKeyPair::generate_pkcs8(&ALG, &rand)?
            }

            _ => return Err(anyhow!("unsupported")),
        };

        Ok(doc.as_ref().to_vec().into())
    }

    fn public_key(&self) -> Result<SubjectPublicKeyInfo<'_>> {
        match self.algorithm.oids()? {
            (ECPK, ..) => {
                let ec = EcPrivateKey::from_der(self.private_key)?;
                let pk = ec.public_key.ok_or_else(|| anyhow!("missing public key"))?;
                Ok(SubjectPublicKeyInfo {
                    algorithm: self.algorithm,
                    subject_public_key: pk,
                })
            }
            _ => return Err(anyhow!("unsupported")),
        }
    }

    fn signs_with(&self) -> Result<AlgorithmIdentifier<'_>> {
        match self.algorithm.oids()? {
            (ECPK, Some(P256)) => Ok(ES256),
            (ECPK, Some(P384)) => Ok(ES384),
            _ => return Err(anyhow!("unsupported")),
        }
    }

    fn sign(&self, body: &[u8], algo: AlgorithmIdentifier<'_>) -> Result<Vec<u8>> {
        let rng = ring::rand::SystemRandom::new();
        match (self.algorithm.oids()?, algo) {
            ((ECPK, Some(P256)), ES256) => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
                let kp = EcdsaKeyPair::from_pkcs8(&ALG, &self.to_vec()?)?;
                Ok(kp.sign(&rng, body)?.as_ref().to_vec())
            }

            ((ECPK, Some(P384)), ES384) => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING as ALG};
                let kp = EcdsaKeyPair::from_pkcs8(&ALG, &self.to_vec()?)?;
                Ok(kp.sign(&rng, body)?.as_ref().to_vec())
            }

            _ => Err(anyhow!("unsupported")),
        }
    }
}
