// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::launch::IdAuth;
use crate::backend::ByteSized;

use std::fmt::Debug;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;

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
    #[clap(long, required = true)]
    author_key: Utf8PathBuf,

    /// SEV P-384 private key in PEM form
    #[clap(long, required = true)]
    id_key: Utf8PathBuf,

    /// File path to write signature
    #[clap(long, required = true)]
    out: Utf8PathBuf,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let mut sev_auth_key_file =
            File::open(&self.author_key).context("Failed to open SEV author key file")?;
        let mut buffer = String::new();
        sev_auth_key_file.read_to_string(&mut buffer)?;
        let sev_auth_key =
            SigningKey::from_pkcs8_pem(&buffer).context("Failed to parse SEV author key")?;

        let mut sev_id_key_file =
            File::open(&self.id_key).context("Failed to open SEV id key file")?;
        let mut buffer = String::new();
        sev_id_key_file.read_to_string(&mut buffer)?;
        let sev_id_key =
            SigningKey::from_pkcs8_pem(&buffer).context("Failed to parse SEV id key")?;

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
        // Sign the SEV signing key with the SEV author key. This will be removed in the future.
        let sig = sev_auth_key.sign(id_auth.id_key.as_bytes());
        // The r and s values have to be in little-endian order.
        let r = sig.r().as_ref().to_le_bytes();
        let s = sig.s().as_ref().to_le_bytes();
        // and are zero extended to the size of the components in the IdAuth struct.
        id_auth.id_key_sig.component.r[..r.as_slice().len()].copy_from_slice(r.as_slice());
        id_auth.id_key_sig.component.s[..s.as_slice().len()].copy_from_slice(s.as_slice());

        let path = self.out.into_string();

        let f = File::open(path.clone());

        let _ = match f {
            Ok(_) => println!("File found"),
            Err(error) => match error.kind() {
                ErrorKind::NotFound => match File::create(path.clone()) {
                    Ok(_) => println!("Created file"),
                    Err(e) => panic!("Problem creating the file: {:?}", e),
                },
                _ => (),
            },
        };

        std::fs::write(path, id_auth.id_key_sig.as_bytes()).expect("Invalid file path");

        Ok(())
    }
}
