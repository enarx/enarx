// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdout;
use std::process::ExitCode;

use camino::Utf8PathBuf;
use clap::Args;
use rand::thread_rng;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::{BigUint, RsaPrivateKey};

/// Generate SGX key for use with Enarx.
#[derive(Args, Debug)]
pub struct Options {
    /// File path to write SGX key in PEM form
    #[clap(long)]
    out: Option<Utf8PathBuf>,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let mut rng = thread_rng();
        let exp = BigUint::from(3u8);
        let key = RsaPrivateKey::new_with_exp(&mut rng, 384 * 8, &exp)?;

        let res_key = RsaPrivateKey::to_pkcs1_pem(&key, LineEnding::default()).unwrap();

        if let Some(path) = self.out {
            let mut file = File::create(path)?;
            file.write_all(res_key.as_bytes())?;
        } else {
            stdout().write_all(res_key.as_bytes())?;
        }

        Ok(ExitCode::SUCCESS)
    }
}
