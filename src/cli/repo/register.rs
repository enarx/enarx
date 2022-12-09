// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, RepoSpec};

use std::ffi::OsString;
use std::process::ExitCode;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use drawbridge_client::types::RepositoryConfig;
use oauth2::url::Url;

/// Register a new repository.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_CA_BUNDLE")]
    ca_bundle: Option<Utf8PathBuf>,
    #[clap(long, default_value = "https://auth.profian.com/")]
    oidc_domain: Url,
    #[clap(long, env = "ENARX_INSECURE_AUTH_TOKEN")]
    insecure_auth_token: Option<String>,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
    spec: RepoSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let cl = client(
            self.spec.host,
            self.oidc_domain,
            self.insecure_auth_token,
            self.ca_bundle,
            self.credential_helper,
        )?;
        let repo = cl.repository(&self.spec.ctx);
        let repo_config = RepositoryConfig {
            // TODO: support deploying from private repos
            public: true,
        };
        repo.create(&repo_config)
            .context("Failed to register repository")?;
        Ok(ExitCode::SUCCESS)
    }
}
