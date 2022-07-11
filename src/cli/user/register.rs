// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, get_token, login, UserSpec};

use std::ffi::OsString;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use drawbridge_client::types::UserRecord;
use drawbridge_client::Url;
use oauth2::AccessToken;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreUserInfoClaims};
use openidconnect::ureq::http_client;
use openidconnect::{AuthType, ClientId, IssuerUrl};

/// Register a new user account with a package host.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_CA_BUNDLE")]
    ca_bundle: Option<Utf8PathBuf>,
    #[clap(long, env = "ENARX_INSECURE_AUTH_TOKEN")]
    insecure_auth_token: Option<String>,
    #[clap(long, env = "ENARX_CREDENTIAL_HELPER")]
    credential_helper: Option<OsString>,
    #[clap(long, default_value = "https://auth.profian.com/")]
    oidc_domain: Url,
    #[clap(long, default_value = "4NuaJxkQv8EZBeJKE56R57gKJbxrTLG2")]
    oidc_client_id: String,
    spec: UserSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let Self {
            ref ca_bundle,
            ref insecure_auth_token,
            ref oidc_domain,
            oidc_client_id,
            ref spec,
            ref credential_helper,
        } = self;

        // If we don't find a token saved locally, initiate an interactive login
        let token = match get_token(insecure_auth_token, credential_helper) {
            Ok(token) => token,
            _ => login(oidc_domain, oidc_client_id.clone(), credential_helper)?,
        };

        let cl = client(
            &spec.host,
            &Some(token.clone()),
            ca_bundle,
            credential_helper,
        )?;
        let user = cl.user(&spec.ctx);

        let provider_metadata = CoreProviderMetadata::discover(
            &IssuerUrl::new(oidc_domain.to_string()).context("Failed to construct issuer URL")?,
            http_client,
        )
        .context("Failed to discover provider metadata")?;

        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(oidc_client_id),
            None,
        )
        .set_auth_type(AuthType::RequestBody);

        let userinfo: CoreUserInfoClaims = oidc_client
            .user_info(AccessToken::new(token), None)
            .context("Failed to find user info endpoint")?
            .request(http_client)
            .context("Failed to make user info request")?;

        let subject = userinfo.subject().to_string();

        let record = UserRecord { subject };

        user.create(&record)
            .context("Failed to register new user")?;

        Ok(())
    }
}
