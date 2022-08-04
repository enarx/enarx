// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdout;

use camino::Utf8PathBuf;
use clap::Args;
use elliptic_curve::SecretKey;
use p384::ecdsa::SigningKey;
use p384::pkcs8::LineEnding;
use p384::{elliptic_curve, pkcs8, NistP384};
use pkcs8::EncodePrivateKey;

/// Generate an SEV key for use with Enarx.
#[derive(Args, Debug)]
pub struct Options {
    /// File path to write SEV key in PEM form
    #[clap(long)]
    out: Option<Utf8PathBuf>,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let rng = rand::thread_rng();
        let signing_key = SigningKey::random(rng);

        // somehow SigningKey does not implement EncodePrivateKey
        // so create a SecretKey and use it to encode the key
        let key: SecretKey<NistP384> = SecretKey::from_be_bytes(signing_key.to_bytes().as_slice())?;
        let res_key = key.to_pkcs8_pem(LineEnding::default())?;

        if let Some(path) = self.out {
            let mut file = File::create(path)?;
            file.write_all(res_key.as_bytes())?;
        } else {
            stdout().write_all(res_key.as_bytes())?;
        }

        Ok(())
    }
}
