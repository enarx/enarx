// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::str::from_utf8;

use async_std::net::{Ipv4Addr, TcpListener};
use async_std::task::{spawn, JoinHandle};
use drawbridge_server::{App, OidcConfig, TlsConfig};
use futures::channel::oneshot::{channel, Sender};
use futures::{join, StreamExt};
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
use tempfile::tempdir;

pub fn enarx(args: String) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_enarx"));

    for arg in args.split_whitespace().skip(1) {
        cmd.arg(arg);
    }

    let out = cmd.output().expect("failed to execute `enarx`");

    Output {
        success: out.status.success(),
        output: from_utf8(&out.stdout).unwrap().to_string(),
        err: from_utf8(&out.stderr).unwrap().to_string(),
    }
}

#[allow(dead_code)]
pub struct Output {
    pub success: bool,
    pub output: String,
    pub err: String,
}

pub async fn run(commands: impl FnOnce(String, String)) {
    env_logger::builder().is_test(true).init();
    let (oidc_addr, oidc_tx, oidc_handle) = init_oidc().await;
    let (db_port, db_tx, db_handle) = init_drawbridge(oidc_addr.clone()).await;
    let db_addr = format!("localhost:{db_port}");

    commands(oidc_addr, db_addr);

    // Gracefully stop servers
    assert_eq!(oidc_tx.send(()), Ok(()));
    assert_eq!(db_tx.send(()), Ok(()));
    assert!(matches!(join!(oidc_handle, db_handle), ((), ())));
}

async fn init_oidc() -> (String, Sender<()>, JoinHandle<()>) {
    let oidc_lis = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("failed to bind to address");

    let oidc_addr = oidc_lis.local_addr().unwrap();

    let oidc_url = format!("http://{oidc_addr}");

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

                        let oidc_url = format!("http://{oidc_addr}/");
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
                                assert_eq!(
                                    auth.as_str().split_once(' '),
                                    Some(("Bearer", "test-token")),
                                );
                                json_response(&CoreUserInfoClaims::new(
                                    StandardClaims::new(SubjectIdentifier::new(
                                        "test|subject".into(),
                                    )),
                                    EmptyAdditionalClaims {},
                                ))
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

async fn init_drawbridge(oidc_addr: String) -> (u16, Sender<()>, JoinHandle<()>) {
    let db_lis = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("failed to bind to address");

    let store = tempdir().expect("failed to create temporary store directory");

    let (db_tx, db_rx) = channel();

    let db_port = db_lis.local_addr().unwrap().port();

    let db_handle = spawn(async move {
        let tls = TlsConfig::read(
            include_bytes!("testdata/server.crt").as_slice(),
            include_bytes!("testdata/server.key").as_slice(),
            include_bytes!("testdata/ca.crt").as_slice(),
        )
        .unwrap();

        let app = App::new(
            store.path(),
            tls,
            OidcConfig {
                label: "test-label".into(),
                issuer: oidc_addr.parse().unwrap(),
                client_id: "test-client-id".into(),
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
