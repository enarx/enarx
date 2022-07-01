// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, RepoSpec};

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use drawbridge_client::types::RepositoryConfig;

/// Register a new repository.
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
        let repo_config = RepositoryConfig {
            // TODO: support deploying from private repos
            public: true,
        };
        repo.create(&repo_config)
            .context("Failed to register repository")?;
        Ok(())
    }
}
