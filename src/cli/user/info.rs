// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, UserSpec};

use std::ffi::OsString;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;

/// Retrieve information about a user account on an Enarx package host.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_CA_BUNDLE")]
    ca_bundle: Option<Utf8PathBuf>,
    #[clap(long, env = "ENARX_INSECURE_AUTH_TOKEN")]
    insecure_auth_token: Option<String>,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
    spec: UserSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let cl = client(
            &self.spec.host,
            &self.insecure_auth_token,
            &self.ca_bundle,
            &self.credential_helper,
        )?;
        let user = cl.user(&self.spec.ctx);
        let record = user
            .get()
            .with_context(|| format!("Failed to get record for user: {}", self.spec.ctx.name))?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        Ok(())
    }
}
