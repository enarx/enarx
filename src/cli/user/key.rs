// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{generate_signing_key, get_signing_key, UserSpec};

use std::ffi::OsString;

use clap::Args;

/// Generate and display keys used for signing uploaded packages
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long)]
    generate: bool,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
    spec: UserSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        if self.generate {
            generate_signing_key(&self.spec, &self.credential_helper)?;
        } else {
            let public_key_jwk = get_signing_key(&self.spec, &self.credential_helper)?;
            println!("{public_key_jwk}");
        }

        Ok(())
    }
}
