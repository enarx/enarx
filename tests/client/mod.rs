// SPDX-License-Identifier: Apache-2.0

mod util;

use util::{enarx, run};

use std::env;
use std::path::Path;

use tempfile::Builder;

/// A nice wrapper over `format!` for testing CLI invocations
macro_rules! cmd {
    (succeed: $args:expr) => {
        enarx(format!($args), true, String::new())
    };
    (succeed: $args:expr, $output:expr) => {
        enarx(format!($args), true, format!($output))
    };
    (fail: $args:expr, $output:expr) => {
        enarx(format!($args), false, format!($output))
    };
}

#[async_std::test]
async fn full() {
    run(|oidc_addr, db_addr| {
        let workspace_dir = env!("CARGO_MANIFEST_DIR");

        env::set_var("ENARX_OIDC_DOMAIN", &oidc_addr);
        env::set_var("ENARX_INSECURE_AUTH_TOKEN", "test-token");
        env::set_var("ENARX_CA_BUNDLE", format!("{workspace_dir}/tests/data/tls/ca.crt"));

        cmd!(
            fail: // when looking up a user that does not exist
            "enarx user info {db_addr}/testuser",
            "Error: Failed to get record for user: testuser

Caused by:
    0: GET request failed
    1: request failed with status code `401`
    2: User with OpenID Connect subject `test|subject` not found
"
        );

        cmd!(
            fail: // when registering user without proper credentials
            "enarx user register --insecure-auth-token bad-token {db_addr}/testuser",
            "Error: Failed to make user info request

Caused by:
    0: Request failed
    1: ureq request failed
    2: {oidc_addr}/userinfo: status code 401
"
        );

        cmd!(
            succeed: // when registering user with proper credentials
            "enarx user register {db_addr}/testuser"
        );

        cmd!(
            fail: // when creating a user whose subject matches an existing user
            "enarx user register {db_addr}/testuser2",
            "Error: Failed to register new user

Caused by:
    0: request failed with status code `409`
    1: User already associated with OpenID Connect subject `test|subject`
"
        );

        cmd!(
            succeed: // when looking up a user that exists
            "enarx user info {db_addr}/testuser",
            r#"{{
  "subject": "test|subject"
}}
"#
        );

        cmd!(
            fail: // when looking up a repo that does not exist
            "enarx repo info {db_addr}/testuser/publicrepo",
            "Error: Failed to retrieve repository information

Caused by:
    0: GET request failed
    1: request failed with status code `404`
    2: Repository does not exist
"
        );

        cmd!(
            succeed: // when registering a public repo
            "enarx repo register {db_addr}/testuser/publicrepo"
        );

        cmd!(
            succeed: // when fetching tags from empty public repo
            "enarx repo info {db_addr}/testuser/publicrepo",
            r#"{{
  "config": {{
    "public": true
  }},
  "tags": []
}}
"#
        );

        cmd!(
            fail: // when looking up a package that does not exist
            "enarx package info {db_addr}/testuser/publicrepo:0.1.0",
            "Error: Failed to retrieve package information

Caused by:
    0: GET request failed
    1: request failed with status code `404`
    2: Repository does not exist
"
        );

        cmd!(
            fail: // when publishing an invalid file as a public package
            "enarx package publish
             {db_addr}/testuser/publicrepo:0.0.0
             {workspace_dir}/tests/client/data/invalid_dir/invalid_file",
            "Error: Invalid file name: {workspace_dir}/tests/client/data/invalid_dir/invalid_file
"
        );

        cmd!(
            fail: // when publishing an invalid directory as a public package
            "enarx package publish
             {db_addr}/testuser/publicrepo:0.0.0
             {workspace_dir}/tests/client/data/invalid_dir",
            "Error: Invalid file name: {workspace_dir}/tests/client/data/invalid_dir/invalid_file
"
        );

        cmd!(
            succeed: // when publishing a main.wasm file as a public package
            "enarx package publish
             {db_addr}/testuser/publicrepo:1.0.0
             {workspace_dir}/tests/client/data/wasm_example/main.wasm"
        );

        cmd!(
            succeed: // when fetching tags from a non-empty public repo
            "enarx repo info {db_addr}/testuser/publicrepo",
            r#"{{
  "config": {{
    "public": true
  }},
  "tags": [
    "1.0.0"
  ]
}}
"#
        );

        cmd!(
            succeed: // when publishing a directory as a public package
            "enarx package publish
             {db_addr}/testuser/publicrepo:2.0.0
             {workspace_dir}/tests/client/data/wasm_example"
        );

        cmd!(
            succeed: // when looking up a public package that exists
            "enarx package info {db_addr}/testuser/publicrepo:2.0.0",
            r#"{{
  "digest": {{
    "sha-224": "ipv22ZRLXTRv4MypL2IVaZypKHb91PgAqWXG6w==",
    "sha-256": "Jcdf/Q0urZed/9dKu9IBq/BtWIHcvSGlsrUWkS1Rx+E=",
    "sha-384": "f52Mxw0vy4KHhk4MAKzfo3xfvi1sM+YpMhBaQvHMB2vGs378nyAADtEYxPlUnUoI",
    "sha-512": "3weINHlihNmslwpckBdzARz4LdTMYsg+L1prU+u1FmwedBnYmpOIEB1Yix4kR3o4G4pbw+JLiSTBftGwLjFrqA=="
  }},
  "length": 707,
  "type": "application/vnd.drawbridge.directory.v1+json"
}}
"#
        );

        // TODO: fetch package
        // TODO: deploy package
    })
    .await;
}

#[test]
fn test_config_init() {
    let tmpdir = Builder::new().prefix("test_config_init").tempdir().unwrap();
    env::set_current_dir(tmpdir.path()).unwrap();
    cmd!(succeed: "enarx config init");
    cmd!(fail: "enarx config init", "Error: \"Enarx.toml\" does already exist.\n");
    assert_eq!(Path::new("Enarx.toml").exists(), true);
}
