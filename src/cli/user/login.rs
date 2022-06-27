// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use anyhow::Context;
use clap::Args;
use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::ureq::http_client;
use oauth2::url::Url;
use oauth2::{AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, TokenResponse, TokenUrl};

/// Log in to an Enarx package host and save credentials locally.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, default_value = "https://auth.profian.com/")]
    domain: Url,
    #[clap(long, default_value = "4NuaJxkQv8EZBeJKE56R57gKJbxrTLG2")]
    client_id: String,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let Self { domain, client_id } = self;

        let dev_auth_url = DeviceAuthorizationUrl::new(format!("{domain}oauth/device/code"))
            .context("Failed to construct device authorization URL")?;
        let auth_url = AuthUrl::new(format!("{domain}authorize"))
            .context("Failed to construct authorization URL")?;
        let token_url = TokenUrl::new(format!("{domain}oauth/token"))
            .context("Failed to construct token URL")?;

        let client = BasicClient::new(ClientId::new(client_id), None, auth_url, Some(token_url))
            .set_auth_type(AuthType::RequestBody)
            .set_device_authorization_url(dev_auth_url);

        let details: StandardDeviceAuthorizationResponse = client
            .exchange_device_code()
            .context("Failed to construct device authorization request")?
            .add_scope(Scope::new("openid".into()))
            .request(http_client)
            .context("Failed to request device code")?;

        println!(
            "To continue, open the following link in your browser:\n\
             \t{}\n\
             At the prompt, enter the following one-time code:\n\
             \t{}\n\
             Once entered, please wait a few moments for authorization to complete.",
            details.verification_uri().as_str(),
            details.user_code().secret()
        );

        let res = client
            .exchange_device_access_token(&details)
            .request(http_client, poll_delay, None)
            .context("Failed to exchange device code for a token")?;

        // TODO: graceful timeout, so that users are not forced to Ctrl+C if the server errors
        let secret = res.access_token().secret();
        keyring::Entry::new("drawbridge", "enarx")
            .set_password(secret)
            .context("Failed to save user credentials")?;
        println!("Credentials received and saved. Login successful.");

        Ok(())
    }
}

const INTERVAL: Duration = Duration::from_secs(3);

/// This function controls how often the final step of the device flow will
/// poll the server to see if the user has finished entering their one-time code.
/// By default the oauth2 crate will start with a sleep interval of 5 seconds
/// and double the interval every time it elapses, which makes for extremely
/// poor user experience, because users can easily be forced to wait more
/// than 40 seconds staring at a command line that's providing no visible feedback.
/// Instead, we politely decline the exponential backoff by ignoring their passed-in
/// duration and always sleep for a fixed number of seconds,
/// making for a dramatically more responsive CLI.
fn poll_delay(_: Duration) {
    std::thread::sleep(INTERVAL);
}
