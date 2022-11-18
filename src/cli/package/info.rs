// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, TagSpec};

use std::ffi::OsString;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use oauth2::url::Url;

/// Retrieve information about a published package.
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
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let cl = client(
            self.spec.host,
            self.oidc_domain,
            self.insecure_auth_token,
            self.ca_bundle,
            self.credential_helper,
        )?;
        let tag = cl.tag(&self.spec.ctx);
        let tag_entry = tag
            .get()
            .context("Failed to retrieve package information")?;
        println!("{}", serde_json::to_string_pretty(&tag_entry)?);

        Ok(())
    }
}
