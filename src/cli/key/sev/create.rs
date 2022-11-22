// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdout;

use camino::Utf8PathBuf;
use clap::Args;
use p384::ecdsa::SigningKey;
use p384::pkcs8::{self, LineEnding};
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

        let res_key = signing_key.to_pkcs8_pem(LineEnding::default())?;

        if let Some(path) = self.out {
            let mut file = File::create(path)?;
            file.write_all(res_key.as_bytes())?;
        } else {
            stdout().write_all(res_key.as_bytes())?;
        }

        Ok(())
    }
}
