// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::launch::IdAuth;
use crate::backend::ByteSized;

use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;

use anyhow::{bail, Context};
use camino::Utf8PathBuf;
use clap::Args;
use p384::ecdsa::signature::Signer as _;
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::sec1::Coordinates;
use p384::pkcs8::DecodePrivateKey;
use p384::EncodedPoint;

/// Generate SEV Signature for provided SEV keys and write to file.
#[derive(Args, Debug)]
pub struct Options {
    /// SEV P-384 private key in PEM form
    #[clap(long)]
    author_key: Utf8PathBuf,

    /// SEV P-384 private key in PEM form
    #[clap(long)]
    id_key: Utf8PathBuf,

    /// File path to write signature
    #[clap(long)]
    out: Utf8PathBuf,
}

pub fn sign_id_sev_key(
    sev_author_key: &SigningKey,
    sev_id_key: &SigningKey,
) -> anyhow::Result<Vec<u8>> {
    let mut id_auth = IdAuth {
        id_key_algo: 1,   // ECDSA P-384 with SHA-384.
        auth_key_algo: 1, // ECDSA P-384 with SHA-384.
        ..Default::default()
    };

    let verifying_key: EncodedPoint = sev_id_key.verifying_key().to_encoded_point(false);
    let (mut r, mut s) = match verifying_key.coordinates() {
        Coordinates::Uncompressed { x, y } => (x.to_vec(), y.to_vec()),
        _ => bail!("Invalid verifying key"),
    };
    // The r and s values have to be in little-endian order
    r.reverse();
    s.reverse();
    // and are zero extended to the size of the components in the IdAuth struct.
    id_auth.id_key.component.r[..r.len()].copy_from_slice(&r);
    id_auth.id_key.component.s[..s.len()].copy_from_slice(&s);
    // Sign the SEV signing key with the SEV author key.
    let sig = sev_author_key.sign(id_auth.id_key.as_bytes());
    // The r and s values have to be in little-endian order.
    let r = sig.r().as_ref().to_le_bytes();
    let s = sig.s().as_ref().to_le_bytes();
    // and are zero extended to the size of the components in the IdAuth struct.
    id_auth.id_key_sig.component.r[..r.as_slice().len()].copy_from_slice(r.as_slice());
    id_auth.id_key_sig.component.s[..s.as_slice().len()].copy_from_slice(s.as_slice());

    // get the coordinates of the public key of the SEV author key.
    let verifying_key: EncodedPoint = sev_author_key.verifying_key().to_encoded_point(false);
    let (mut r, mut s) = match verifying_key.coordinates() {
        Coordinates::Uncompressed { x, y } => (x.to_vec(), y.to_vec()),
        _ => bail!("Invalid verifying key"),
    };
    // The r and s values have to be in little-endian order.
    r.reverse();
    s.reverse();
    // and are zero extended to the size of the components in the IdAuth struct.
    id_auth.author_key.component.r[..r.len()].copy_from_slice(&r);
    id_auth.author_key.component.s[..s.len()].copy_from_slice(&s);

    let mut buf = Vec::new();
    buf.write_all(id_auth.id_key_sig.as_bytes()).unwrap();
    buf.write_all(id_auth.author_key.as_bytes()).unwrap();
    Ok(buf)
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let mut sev_author_key_file =
            File::open(&self.author_key).context("Failed to open SEV author key file")?;
        let mut buffer = String::new();
        sev_author_key_file.read_to_string(&mut buffer)?;
        let sev_author_key =
            SigningKey::from_pkcs8_pem(&buffer).context("Failed to parse SEV author key")?;

        let mut sev_id_key_file =
            File::open(&self.id_key).context("Failed to open SEV id key file")?;
        let mut buffer = String::new();
        sev_id_key_file.read_to_string(&mut buffer)?;
        let sev_id_key =
            SigningKey::from_pkcs8_pem(&buffer).context("Failed to parse SEV id key")?;

        let buf = sign_id_sev_key(&sev_author_key, &sev_id_key)?;

        let mut f = File::create(self.out.as_path())
            .with_context(|| format!("Failed to create output file {}", self.out))?;

        f.write_all(&buf)
            .with_context(|| format!("Failed to write to output file {}", self.out))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::cli::key::sev::sign::sign_id_sev_key;
    use p384::ecdsa::SigningKey;
    use p384::pkcs8::DecodePrivateKey;

    const SEV_ID_KEY: &str = include_str!("../../../../tests/data/sev-id.key");
    const SEV_AUTHOR_KEY: &str = include_str!("../../../../tests/data/sev-author.key");
    const SEV_ID_KEY_SIG_BLOB: &[u8] =
        include_bytes!("../../../../tests/data/sev-id-key-signature.blob");

    #[test]
    fn test_sev_vector() {
        let author_key = SigningKey::from_pkcs8_pem(SEV_AUTHOR_KEY).unwrap();
        let id_key = SigningKey::from_pkcs8_pem(SEV_ID_KEY).unwrap();
        let buf = sign_id_sev_key(&author_key, &id_key).unwrap();

        assert_eq!(SEV_ID_KEY_SIG_BLOB, buf.as_slice());
    }
}
