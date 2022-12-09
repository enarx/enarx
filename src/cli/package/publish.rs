// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, TagSpec};

use std::ffi::OsString;
use std::fs::read_dir;
use std::process::ExitCode;

use anyhow::{bail, Context};
use camino::Utf8PathBuf;
use clap::Args;
use oauth2::url::Url;

/// Publish a new package.
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
    spec: TagSpec,
    path: Utf8PathBuf,
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

        // TODO: this logic should live in Drawbridge, so that it can be reused for the server
        if self.path.is_file() {
            self.path
                .file_name()
                .filter(|&name| name == "main.wasm")
                .with_context(|| format!("Invalid file name: {}", self.path))?;
        } else {
            for entry in read_dir(self.path.clone())? {
                let path = entry?.path();
                if path.is_file() {
                    path.file_name()
                        .filter(|&name| name == "main.wasm" || name == "Enarx.toml")
                        .with_context(|| format!("Invalid file name: {}", path.display()))?;
                } else {
                    bail!("Publishing nested directories is not supported")
                }
            }
        }

        let tag = cl.tag(&self.spec.ctx);
        let (_tag_created, _tree_created) = tag
            .create_from_path_unsigned(self.path)
            .context("Failed to create tag and upload tree")?;

        Ok(ExitCode::SUCCESS)
    }
}
