// SPDX-License-Identifier: Apache-2.0

use super::oidc_client_secret;
use crate::drawbridge::{LoginContext, OidcLoginFlow};

use std::ffi::OsString;
use std::process::ExitCode;

use clap::Args;
use oauth2::url::Url;

/// Log in to an Enarx package host and save credentials locally.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(
        long,
        env = "ENARX_OIDC_DOMAIN",
        default_value = "https://auth.profian.com/"
    )]
    oidc_domain: Url,
    #[clap(long, default_value = "4NuaJxkQv8EZBeJKE56R57gKJbxrTLG2")]
    oidc_client_id: String,
    #[clap(long, default_value = "device")]
    oidc_flow: OidcLoginFlow,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
    #[clap(long, default_value = "store.profian.com")]
    store_host: String,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let Self {
            ref oidc_domain,
            oidc_client_id,
            oidc_flow,
            credential_helper,
            ref store_host,
        } = self;
        let oidc_client_secret = oidc_client_secret()?;
        let credential_helper = credential_helper.as_ref().map(AsRef::as_ref);

        LoginContext {
            host: store_host,
            oidc_domain,
            oidc_client_id,
            oidc_client_secret,
            oidc_flow,
            credential_helper,
        }
        .login()?;

        println!("Login successful.");

        Ok(ExitCode::SUCCESS)
    }
}
