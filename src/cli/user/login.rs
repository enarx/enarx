// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::login;

use std::ffi::OsString;

use clap::Args;
use oauth2::url::Url;

/// Log in to an Enarx package host and save credentials locally.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, default_value = "https://auth.profian.com/")]
    oidc_domain: Url,
    #[clap(long, default_value = "4NuaJxkQv8EZBeJKE56R57gKJbxrTLG2")]
    oidc_client_id: String,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let Self {
            ref oidc_domain,
            oidc_client_id,
            ref credential_helper,
        } = self;

        login(oidc_domain, oidc_client_id, credential_helper)?;

        println!("Login successful.");

        Ok(())
    }
}
