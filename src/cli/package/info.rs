// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, TagSpec};

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;

/// Retrieve information about a published package.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_CA_BUNDLE")]
    ca_bundle: Option<Utf8PathBuf>,
    #[clap(long, env = "ENARX_INSECURE_AUTH_TOKEN")]
    insecure_auth_token: Option<String>,
    spec: TagSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let cl = client(self.spec.host, self.insecure_auth_token, self.ca_bundle)?;
        let tag = cl.tag(&self.spec.ctx);
        let tag_entry = tag
            .get()
            .context("Failed to retrieve package information")?;
        println!("{}", serde_json::to_string_pretty(&tag_entry)?);

        Ok(())
    }
}
