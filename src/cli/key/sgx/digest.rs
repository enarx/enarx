// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdout;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};
use sha2::{Digest, Sha256};

/// Generate Digest for provided SGX key and write to file.
#[derive(Args, Debug)]
pub struct Options {
    /// SGX private key in PEM form
    #[clap(value_name = "SGX KEY")]
    key: Utf8PathBuf,

    /// File path to write digest
    #[clap(long)]
    out: Option<Utf8PathBuf>,
}

fn arr_from_big(value: &BigUint) -> [u8; 384] {
    let mut arr = [0u8; 384];
    let buf = value.to_bytes_le();
    arr[..buf.len()].copy_from_slice(&buf);
    arr
}

pub fn sgx_key_digest(sgx_key: &RsaPrivateKey) -> anyhow::Result<Vec<u8>> {
    let modulus = arr_from_big(sgx_key.n());

    let mut hasher = Sha256::new();
    hasher.update(&modulus);
    let res = hasher.finalize();
    Ok(res.to_vec())
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let mut sgx_key = File::open(&self.key).context("Failed to open SGX key file")?;
        let mut buffer = String::new();
        sgx_key.read_to_string(&mut buffer)?;
        let sgx_key = RsaPrivateKey::from_pkcs1_pem(&buffer).context("Failed to parse SGX key")?;

        let res = sgx_key_digest(&sgx_key)?;
        let out = hex::encode(res);

        if let Some(path) = self.out {
            let mut file = File::create(path)?;
            file.write_all(out.as_bytes())?;
        } else {
            stdout().write_all(out.as_bytes())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::sgx_key_digest;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;

    const SGX_KEY: &str = include_str!("../../../../tests/data/sgx-test.key");

    #[test]
    fn test_digest() {
        let key = RsaPrivateKey::from_pkcs1_pem(SGX_KEY).unwrap();
        let digest = sgx_key_digest(&key).unwrap();
        assert_eq!(
            digest,
            hex::decode("298037d88782e022e019b3020745b78aa40ed95c77da4bf7f3253d3a44c4fd7e")
                .unwrap()
        );
    }
}
