// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, TagSpec};

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;

/// Publish a new package.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_CA_BUNDLE")]
    ca_bundle: Option<Utf8PathBuf>,
    #[clap(long, env = "ENARX_INSECURE_AUTH_TOKEN")]
    insecure_auth_token: Option<String>,
    spec: TagSpec,
    path: Utf8PathBuf,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let cl = client(self.spec.host, self.insecure_auth_token, self.ca_bundle)?;
        let tag = cl.tag(&self.spec.ctx);
        let (_tag_created, _tree_created) = tag
            .create_from_path_unsigned(self.path)
            .context("Failed to create tag and upload tree")?;

        Ok(())
    }
}
