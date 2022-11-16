// SPDX-License-Identifier: Apache-2.0

use Output::{Json, Text};

use std::fmt;
use std::process::Command;
use std::str::from_utf8;

use async_std::net::{Ipv4Addr, TcpListener};
use async_std::task::{spawn, JoinHandle};
use drawbridge_server::{App, OidcConfig, TlsConfig};
use futures::channel::oneshot::{channel, Sender};
use futures::StreamExt;
use http_types::convert::{json, Serialize};
use http_types::{Body, Response, StatusCode};
use openidconnect::core::{
    CoreJsonWebKey, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreResponseType, CoreSubjectIdentifierType, CoreUserInfoClaims,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl,
    ResponseTypes, StandardClaims, SubjectIdentifier, UserInfoUrl,
};
use serde_json::{from_slice, to_string_pretty, Value};
use tempfile::tempdir;

/// A nice wrapper over `format!` for testing CLI invocations
macro_rules! cmd {
    // A command that succeeds with blank output
    (succeed: $args:expr) => {
        util::enarx(format!($args), true, util::Output::Text(String::new()))
    };
    // A command that succeeds with text output
    (succeed: $args:expr, text: $output:expr) => {
        util::enarx(format!($args), true, util::Output::Text(format!($output)))
    };
    // A command that succeeds with JSON output
    (succeed: $args:expr, json: $output:tt) => {
        util::enarx(
            format!($args),
            true,
            util::Output::Json(serde_json::json!($output)),
        )
    };
    // A command that fails with text output
    (fail: $args:expr, text: $output:expr) => {
        util::enarx(format!($args), false, util::Output::Text(format!($output)))
    };
}

#[track_caller]
pub fn enarx(input: String, expected_success: bool, expected_output: Output) {
    let args = shell_words::split(&input).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_enarx"));

    // Disable RUST_BACKTRACE when running the tests so as not to cause spurious
    // failures when comparing the actual output to the expected output.
    // This is convenient for users who have RUST_BACKTRACE set by default
    // in their development environment and want to run the tests.
    cmd.env_remove("RUST_BACKTRACE");

    for arg in args.iter().skip(1) {
        cmd.arg(arg);
    }

    let res = cmd.output().expect("failed to execute `enarx`");

    let succeeded = res.status.success();

    let combined = [res.stdout, res.stderr].concat();

    let output = match expected_output {
        Json(_) => Json(from_slice(&combined).unwrap()),
        Text(_) => Text(from_utf8(&combined).unwrap().trim_end().to_string()),
    };

    let failed_test = if expected_success && !succeeded {
        Some("expected command to succeed, but it failed")
    } else if !expected_success && succeeded {
        Some("expected command to fail, but it succeeded")
    } else if output != expected_output {
        Some("expected output differs from received output")
    } else {
        None
    };

    if let Some(msg) = failed_test {
        panic!(
            "{msg}:\n\n\
            ```command\n\
            {input}\n\
            ```\n\n\
            ```expected\n\
            {expected_output}\n\
            ```\n\n\
            ```received\n\
            {output}\n\
            ```\n"
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Output {
    Json(Value),
    Text(String),
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Json(json) => write!(f, "{}", to_string_pretty(json).unwrap()),
            Text(text) => write!(f, "{text}"),
        }
    }
}

pub async fn init_oidc() -> (String, Sender<()>, JoinHandle<()>) {
    let oidc_lis = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("failed to bind to address");

    let oidc_host = oidc_lis.local_addr().unwrap();

    let oidc_url = format!("http://{oidc_host}");

    let (oidc_tx, oidc_rx) = channel();

    let oidc_handle = spawn(async move {
        oidc_lis
            .incoming()
            .take_until(oidc_rx)
            .for_each_concurrent(None, |stream| async {
                async_h1::accept(
                    stream.expect("failed to initialize stream"),
                    |req| async move {
                        fn json_response(
                            body: &impl Serialize,
                        ) -> Result<Response, http_types::Error> {
                            let mut res = Response::new(StatusCode::Ok);
                            res.insert_header("Content-Type", "application/json");
                            let body = Body::from_json(&json!(body))?;
                            res.set_body(body);
                            Ok(res)
                        }

                        let oidc_url = format!("http://{oidc_host}/");
                        match req.url().path() {
                            "/.well-known/openid-configuration" => {
                                json_response(
                                    &CoreProviderMetadata::new(
                                        // Parameters required by the OpenID Connect Discovery spec.
                                        IssuerUrl::new(oidc_url.to_string()).unwrap(),
                                        AuthUrl::new(format!("{oidc_url}authorize")).unwrap(),
                                        // Use the JsonWebKeySet struct to serve the JWK Set at this URL.
                                        JsonWebKeySetUrl::new(format!("{oidc_url}jwks")).unwrap(),
                                        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
                                        vec![CoreSubjectIdentifierType::Pairwise],
                                        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
                                        EmptyAdditionalProviderMetadata {},
                                    )
                                    .set_userinfo_endpoint(
                                        Some(
                                            UserInfoUrl::new(format!("{oidc_url}userinfo"))
                                                .unwrap(),
                                        ),
                                    ),
                                )
                            }
                            "/jwks" => json_response(&CoreJsonWebKeySet::new(vec![
                                CoreJsonWebKey::new_rsa(b"ntest".to_vec(), b"etest".to_vec(), None),
                            ])),
                            "/userinfo" => {
                                let auth = req
                                    .header("Authorization")
                                    .expect("Authorization header missing");
                                if auth.as_str().split_once(' ') != Some(("Bearer", "test-token")) {
                                    Ok(Response::new(StatusCode::Unauthorized))
                                } else {
                                    json_response(&CoreUserInfoClaims::new(
                                        StandardClaims::new(SubjectIdentifier::new(
                                            "test|subject".into(),
                                        )),
                                        EmptyAdditionalClaims {},
                                    ))
                                }
                            }
                            p => panic!("Unsupported path requested: `{p}`"),
                        }
                    },
                )
                .await
                .expect("failed to handle OIDC connection");
            })
            .await
    });

    (oidc_url, oidc_tx, oidc_handle)
}

pub async fn init_drawbridge(oidc_url: String) -> (u16, Sender<()>, JoinHandle<()>) {
    let db_lis = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("failed to bind to address");

    let store = tempdir().expect("failed to create temporary store directory");

    let (db_tx, db_rx) = channel();

    let db_port = db_lis.local_addr().unwrap().port();

    let db_handle = spawn(async move {
        let tls = TlsConfig::read(
            include_bytes!("../data/tls/server.crt").as_slice(),
            include_bytes!("../data/tls/server.key").as_slice(),
            include_bytes!("../data/tls/ca.crt").as_slice(),
        )
        .unwrap();

        let app = App::new(
            store.path(),
            tls,
            OidcConfig {
                label: "test-label".into(),
                issuer: oidc_url.parse().unwrap(),
                client_id: "4NuaJxkQv8EZBeJKE56R57gKJbxrTLG2".into(),
                client_secret: None,
            },
        )
        .await
        .unwrap();

        db_lis
            .incoming()
            .take_until(db_rx)
            .for_each_concurrent(None, |stream| async {
                app.handle(stream.expect("failed to initialize stream"))
                    .await
                    .expect("failed to handle stream")
            })
            .await
    });

    (db_port, db_tx, db_handle)
}
