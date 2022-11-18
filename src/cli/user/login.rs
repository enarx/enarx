// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{login, LoginContext, LoginCredentials};

use std::ffi::OsString;

use anyhow::Context;
use clap::{Args, ValueEnum};
use oauth2::url::Url;

#[derive(Debug, Clone, ValueEnum)]
enum LoginMethod {
    ClientCredentials,
    DeviceAuthorization,
}
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
    #[clap(long)]
    #[arg(value_enum)]
    login_method: LoginMethod,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
    #[clap(long, default_value = "store.profian.com")]
    store_host: String,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let Self {
            oidc_domain,
            oidc_client_id,
            login_method,
            credential_helper,
            store_host,
        } = self;

        let oidc_credentials = match login_method {
            LoginMethod::ClientCredentials => LoginCredentials::ClientCredentials {
                client_id: oidc_client_id,
                client_secret: std::env::var("ENARX_OIDC_CLIENT_SECRET")
                    .context("Error getting the ENARX_OIDC_CLIENT_SECRET value")?,
            },
            LoginMethod::DeviceAuthorization => LoginCredentials::DeviceAuthorization {
                client_id: oidc_client_id,
            },
        };

        login(LoginContext {
            host: store_host,
            oidc_domain,
            credentials: oidc_credentials,
            helper: credential_helper,
        })?;

        println!("Login successful.");

        Ok(())
    }
}
