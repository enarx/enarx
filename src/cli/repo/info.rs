// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, RepoSpec};

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use drawbridge_client::types::{RepositoryConfig, TagName};
use serde::Serialize;

#[derive(Serialize)]
struct RepoInfo {
    config: RepositoryConfig,
    tags: Vec<TagName>,
}

/// List all tags associated with a repository.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_CA_BUNDLE")]
    ca_bundle: Option<Utf8PathBuf>,
    #[clap(long, env = "ENARX_INSECURE_AUTH_TOKEN")]
    insecure_auth_token: Option<String>,
    spec: RepoSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let cl = client(self.spec.host, self.insecure_auth_token, self.ca_bundle)?;
        let repo = cl.repository(&self.spec.ctx);
        let config = repo
            .get()
            .context("Failed to retrieve repository information")?;
        let tags = repo.tags().context("Failed to retrieve repository tags")?;
        let info = RepoInfo { config, tags };
        println!("{}", serde_json::to_string_pretty(&info)?);
        Ok(())
    }
}
