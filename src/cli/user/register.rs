// SPDX-License-Identifier: Apache-2.0

use crate::drawbridge::{client, get_token, login, UserSpec};

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
    #[clap(long, default_value = "https://auth.profian.com/")]
    oidc_domain: Url,
    #[clap(long, default_value = "4NuaJxkQv8EZBeJKE56R57gKJbxrTLG2")]
    oidc_client_id: String,
    spec: UserSpec,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        // If we don't find a token saved locally, initiate an interactive login
        let token = match get_token(self.insecure_auth_token.clone()) {
            Ok(token) => token,
            _ => login(self.oidc_domain.clone(), self.oidc_client_id.clone())?,
        };

        let cl = client(self.spec.host, Some(token.clone()), self.ca_bundle)?;
        let user = cl.user(&self.spec.ctx);

        let provider_metadata = CoreProviderMetadata::discover(
            &IssuerUrl::new(self.oidc_domain.to_string())
                .context("Failed to construct issuer URL")?,
            http_client,
        )
        .context("Failed to discover provider metadata")?;

        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.oidc_client_id),
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
