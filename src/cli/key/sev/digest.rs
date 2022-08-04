// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::sign::PublicKey;
use crate::backend::ByteSized;

use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdout;

use anyhow::{bail, Context};
use camino::Utf8PathBuf;
use clap::Args;
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::sec1::Coordinates;
use p384::pkcs8::DecodePrivateKey;
use p384::EncodedPoint;
use sha2::{Digest, Sha384};

/// Generate Digest for provided SEV key and write to file.
#[derive(Args, Debug)]
pub struct Options {
    /// SEV P-384 private key in PEM form
    #[clap(value_name = "SEV KEY")]
    key: Utf8PathBuf,

    /// File path to write digest
    #[clap(long)]
    out: Option<Utf8PathBuf>,
}

fn sev_key_digest(sev_key: &SigningKey) -> anyhow::Result<Vec<u8>> {
    // get the coordinates of the public key of the signing key.
    let verifying_key: EncodedPoint = sev_key.verifying_key().to_encoded_point(false);
    let (mut r, mut s) = match verifying_key.coordinates() {
        Coordinates::Uncompressed { x, y } => (x.to_vec(), y.to_vec()),
        _ => bail!("Invalid verifying key"),
    };
    // The r and s values have to be in little-endian order.
    r.reverse();
    s.reverse();

    let mut res_key = PublicKey::default();

    res_key.component.r[..r.as_slice().len()].copy_from_slice(r.as_slice());
    res_key.component.s[..s.as_slice().len()].copy_from_slice(s.as_slice());

    let mut hasher = Sha384::new();
    hasher.update(res_key.as_bytes());
    let res = hasher.finalize();
    Ok(res.to_vec())
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let mut sev_key_file = File::open(&self.key).context("Failed to open SEV key file")?;
        let mut buffer = String::new();
        sev_key_file.read_to_string(&mut buffer)?;
        let sev_key = SigningKey::from_pkcs8_pem(&buffer).context("Failed to parse SEV key")?;

        let res = sev_key_digest(&sev_key)?;
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
    use super::sev_key_digest;

    use p384::ecdsa::SigningKey;
    use p384::pkcs8::DecodePrivateKey;

    const SEV_ID_KEY: &str = include_str!("../../../../tests/data/sev-id.key");
    const SEV_AUTHOR_KEY: &str = include_str!("../../../../tests/data/sev-author.key");

    #[test]
    fn test_author_digest() {
        let author_key = SigningKey::from_pkcs8_pem(SEV_AUTHOR_KEY).unwrap();
        let digest = sev_key_digest(&author_key).unwrap();
        assert_eq!(digest, hex::decode("0dd83a8c088945ea8577ff94c29ddda82488ddf8b5723299b5b01ef28f10be5388be7af8aa00b06dd9deaeddc74b487a").unwrap());
    }

    #[test]
    fn test_id_digest() {
        let id_key = SigningKey::from_pkcs8_pem(SEV_ID_KEY).unwrap();
        let digest = sev_key_digest(&id_key).unwrap();
        assert_eq!(digest, hex::decode("0ea04f87205f95585f8037850f37104470ac2d79ca42033057fa56926a8ee3f06313f6da3742e2115222d1205ca0a1fe").unwrap());
    }
}
