// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{stderr, Write};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::thread::spawn;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use camino::Utf8PathBuf;
use drawbridge_client::types::{RepositoryContext, TagContext, UserContext};
use drawbridge_client::Client;
use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::ureq::http_client;
use oauth2::url::Url;
use oauth2::{AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, TokenResponse, TokenUrl};
use rustls::{Certificate, RootCertStore};

const DEFAULT_HOST: &str = "store.profian.com";

#[derive(Debug)]
pub struct UserSpec {
    pub host: String,
    pub ctx: UserContext,
}

impl FromStr for UserSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, user) = parse_user(s);
        let ctx = user
            .parse()
            .with_context(|| format!("Invalid user specification: {user}"))?;
        Ok(Self { host, ctx })
    }
}

#[derive(Debug)]
pub struct RepoSpec {
    pub host: String,
    pub ctx: RepositoryContext,
}

impl FromStr for RepoSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, user, repo) = parse_repo(s)
            .with_context(|| format!("Failed to parse repository specification: {s}"))?;
        let ctx = (user, repo)
            .try_into()
            .with_context(|| format!("Invalid repository specification: {repo}"))?;
        Ok(Self { host, ctx })
    }
}

#[derive(Debug)]
pub struct TagSpec {
    pub host: String,
    pub ctx: TagContext,
}

impl FromStr for TagSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, user, repo, tag) =
            parse_tag(s).with_context(|| format!("Failed to parse package specification: {s}"))?;
        let ctx = (user, repo, tag)
            .try_into()
            .with_context(|| format!("Invalid package specification: {tag}"))?;
        Ok(Self { host, ctx })
    }
}

pub fn parse_tag(slug: &str) -> anyhow::Result<(String, &str, &str, &str)> {
    let (head, tag) = slug
        .rsplit_once(':')
        .with_context(|| format!("Missing `:` in tag specification: {slug}"))?;
    let (host, user, repo) = parse_repo(head)?;
    Ok((host, user, repo, tag))
}

fn parse_repo(slug: &str) -> anyhow::Result<(String, &str, &str)> {
    let (head, repo) = slug
        .rsplit_once('/')
        .with_context(|| format!("Missing `/` in repository specification: {slug}"))?;
    let (host, user) = parse_user(head);
    Ok((host, user, repo))
}

fn parse_user(slug: &str) -> (String, &str) {
    let (host, user) = slug.rsplit_once('/').unwrap_or((DEFAULT_HOST, slug));
    (host.to_string(), user)
}

pub fn get_token(
    oidc_domain: &impl Borrow<Url>,
    provided_token: &Option<impl AsRef<str>>,
    helper: &Option<impl AsRef<OsStr>>,
) -> anyhow::Result<String> {
    let oidc_domain = oidc_domain
        .borrow()
        .host_str()
        .ok_or_else(|| anyhow!("invalid OpenID Connect domain"))?;
    if let Some(token) = provided_token {
        Ok(token.as_ref().into())
    } else if let Some(helper) = helper {
        let output = Command::new(helper)
            .arg("show")
            .arg(oidc_domain)
            .output()
            .context("Failed to execute credential helper")?;
        stderr()
            .write_all(&output.stderr)
            .context("Failed to write stderr")?;
        if output.status.success() {
            String::from_utf8(output.stdout).context("Credential helper stdout is not valid UTF-8")
        } else if let Some(code) = output.status.code() {
            bail!("Credential helper failed with exit code {code}")
        } else {
            bail!("Credential helper was killed")
        }
    } else {
        keyring::Entry::new("enarx", oidc_domain)
            .get_password()
            .context("Failed to read credentials from keyring")
    }
}

pub fn client(
    host: &str,
    oidc_domain: &impl Borrow<Url>,
    insecure_token: &Option<String>,
    ca_bundle: &Option<Utf8PathBuf>,
    helper: &Option<impl AsRef<OsStr>>,
) -> anyhow::Result<Client> {
    let token = get_token(oidc_domain, insecure_token, helper)?;

    let url = format!("https://{host}");

    let mut cl = Client::builder(
        url.parse()
            .with_context(|| format!("Failed to parse URL: {url}"))?,
    );

    if let Some(ca_bundle_path) = ca_bundle {
        cl = cl.roots({
            let mut roots = RootCertStore::empty();

            let ca_bundle_file = File::open(ca_bundle_path)?;

            rustls_pemfile::certs(&mut std::io::BufReader::new(ca_bundle_file))
                .unwrap()
                .into_iter()
                .map(Certificate)
                .try_for_each(|ref cert| {
                    roots
                        .add(cert)
                        .with_context(|| format!("Failed to add root certificate: {cert:?}"))
                })?;

            roots
        });
    }

    let cl = cl
        .token(token.trim())
        .build()
        .context("Failed to build client")?;

    Ok(cl)
}

pub fn login(
    oidc_domain: &impl Borrow<Url>,
    oidc_client_id: String,
    helper: &Option<impl AsRef<OsStr>>,
) -> anyhow::Result<String> {
    let oidc_domain = oidc_domain.borrow();
    let dev_auth_url = DeviceAuthorizationUrl::new(format!("{oidc_domain}oauth/device/code"))
        .context("Failed to construct device authorization URL")?;
    let auth_url = AuthUrl::new(format!("{oidc_domain}authorize"))
        .context("Failed to construct authorization URL")?;
    let token_url = TokenUrl::new(format!("{oidc_domain}oauth/token"))
        .context("Failed to construct token URL")?;

    let client = BasicClient::new(
        ClientId::new(oidc_client_id),
        None,
        auth_url,
        Some(token_url),
    )
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
    let oidc_domain = oidc_domain
        .borrow()
        .host_str()
        .ok_or_else(|| anyhow!("invalid OpenID Connect domain"))?;
    let secret = res.access_token().secret();
    if let Some(helper) = helper {
        let mut helper = Command::new(helper)
            .stdin(Stdio::piped())
            .arg("insert")
            .arg(oidc_domain)
            .spawn()
            .context("Failed to spawn credential helper command")?;
        let mut stdin = helper.stdin.take().context("Failed to open stdin")?;
        let secret = secret.clone();
        spawn(move || {
            stdin
                .write_all(secret.as_bytes())
                .context("Failed to write secret to credential helper stdin")
        })
        .join()
        .expect("Failed to join stdin pipe thread")?;
        let output = helper
            .wait()
            .context("Failed to wait for credential helper to exit")?;
        if !output.success() {
            if let Some(code) = output.code() {
                bail!("Credential helper failed with exit code {code}")
            } else {
                bail!("Credential helper was killed")
            }
        }
    } else {
        keyring::Entry::new("enarx", oidc_domain)
            .set_password(secret)
            .context("Failed to save user credentials")?;
    }
    println!("Credentials saved locally.");

    Ok(secret.to_string())
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
