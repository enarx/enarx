// SPDX-License-Identifier: Apache-2.0

#[macro_use]
mod util;

use std::env;
use std::path::Path;

use futures::join;
use tempfile::Builder;

const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

// This is a stateful test that spawns subcommands to exercise the Enarx CLI
// using a local Drawbridge server and a mocked OIDC server.
fn drawbridge_script(oidc_url: String, db_host: String) {
    let data_dir = format!("{WORKSPACE_DIR}/tests/client/data");

    // These environment variables will affect all commands executed below,
    // unless explicitly overridden.
    env::set_var("ENARX_OIDC_DOMAIN", &oidc_url);
    env::set_var("ENARX_INSECURE_AUTH_TOKEN", "test-token");
    env::set_var(
        "ENARX_CA_BUNDLE",
        format!("{WORKSPACE_DIR}/tests/data/tls/ca.crt"),
    );

    // TODO: succeed when logging in with custom credential helper

    cmd!(
        fail: // when looking up a user that does not exist
        "enarx user info {db_host}/testuser",
        text:
        "Error: Failed to get record for user: testuser

Caused by:
    0: GET request failed
    1: request failed with status code `401`
    2: User with OpenID Connect subject `test|subject` not found"
    );

    cmd!(
        fail: // when registering user without proper credentials
        "enarx user register --insecure-auth-token bad-token {db_host}/testuser",
        text:
        "Error: Failed to make user info request

Caused by:
    0: Request failed
    1: ureq request failed
    2: {oidc_url}/userinfo: status code 401"
    );

    // TODO: fail when registering user whose name contains invalid characters
    // TODO: fail when registering user whose name is too long

    cmd!(
        succeed: // when registering user with proper credentials
        "enarx user register {db_host}/testuser"
    );

    cmd!(
        fail: // when creating a user whose subject matches an existing user
        "enarx user register {db_host}/testuser2",
        text:
        "Error: Failed to register new user

Caused by:
    0: request failed with status code `409`
    1: User already associated with OpenID Connect subject `test|subject`"
    );

    cmd!(
        succeed: // when looking up a user that exists
        "enarx user info {db_host}/testuser",
        json: {
            "subject": "test|subject"
        }
    );

    cmd!(
        fail: // when looking up a repo that does not exist
        "enarx repo info {db_host}/testuser/pubrepo",
        text:
        "Error: Failed to retrieve repository information

Caused by:
    0: GET request failed
    1: request failed with status code `404`
    2: Repository does not exist"
    );

    // TODO: fail when registering a repo whose name contains invalid characters
    // TODO: fail when registering a repo whose name is too long

    cmd!(
        succeed: // when registering a public repo
        "enarx repo register {db_host}/testuser/pubrepo"
    );

    // TODO: succeed when registering a private repo

    cmd!(
        succeed: // when fetching tags from an empty public repo
        "enarx repo info {db_host}/testuser/pubrepo",
        json: {
            "config": {
                "public": true
            },
            "tags": []
        }
    );

    // TODO: succeed when fetching tags from an empty private repo

    cmd!(
        fail: // when looking up a package that does not exist
        "enarx package info {db_host}/testuser/pubrepo:0.1.0",
        text:
        "Error: Failed to retrieve package information

Caused by:
    0: GET request failed
    1: request failed with status code `404`
    2: Repository does not exist"
    );

    cmd!(
        fail: // when publishing an invalid file as a public package
        "enarx package publish {db_host}/testuser/pubrepo:0.0.0 {data_dir}/bad_dir/bad_file",
        text:
        "Error: Invalid file name: {data_dir}/bad_dir/bad_file"
    );

    cmd!(
        fail: // when publishing an invalid directory as a public package
        "enarx package publish {db_host}/testuser/pubrepo:0.0.0 {data_dir}/bad_dir",
        text:
        "Error: Invalid file name: {data_dir}/bad_dir/bad_file"
    );

    cmd!(
        succeed: // when publishing a main.wasm file as a public package
        "enarx package publish {db_host}/testuser/pubrepo:1.0.0 {data_dir}/wasm_example/main.wasm"
    );

    cmd!(
        succeed: // when fetching tags from a non-empty public repo
        "enarx repo info {db_host}/testuser/pubrepo",
        json: {
            "config": {
                "public": true
            },
            "tags": [
                "1.0.0"
            ]
        }
    );

    cmd!(
        succeed: // when publishing a directory as a public package
        "enarx package publish {db_host}/testuser/pubrepo:2.0.0 {data_dir}/wasm_example"
    );

    // TODO: succeed when publishing a main.wasm file as a private package
    // TODO: succeed when publishing a directory as a private package

    // TODO: succeed when fetching tags from a non-empty private repo

    cmd!(
        succeed: // when looking up a public package that exists
        "enarx package info {db_host}/testuser/pubrepo:2.0.0",
        json: {
            "digest": {
                "sha-224": "ipv22ZRLXTRv4MypL2IVaZypKHb91PgAqWXG6w==",
                "sha-256": "Jcdf/Q0urZed/9dKu9IBq/BtWIHcvSGlsrUWkS1Rx+E=",
                "sha-384": "f52Mxw0vy4KHhk4MAKzfo3xfvi1sM+YpMhBaQvHMB2vGs378nyAADtEYxPlUnUoI",
                "sha-512": "3weINHlihNmslwpckBdzARz4LdTMYsg+L1prU+u1FmwedBnYmpOIEB1Yix4kR3o4G4pbw+JLiSTBftGwLjFrqA=="
              },
              "length": 707,
              "type": "application/vnd.drawbridge.directory.v1+json"
          }
    );

    // TODO: succeed when looking up a private package that exists
    // TODO: succeed when fetching a public package
    // TODO: fail when fetching a private package
    // TODO: succeed when deploying a public package
    // TODO: succeed when deploying a private package
}

#[async_std::test]
async fn drawbridge() {
    env_logger::builder().is_test(true).init();
    let (oidc_url, oidc_tx, oidc_handle) = util::init_oidc().await;
    let (db_port, db_tx, db_handle) = util::init_drawbridge(oidc_url.clone()).await;
    let db_host = format!("localhost:{db_port}");

    drawbridge_script(oidc_url, db_host);

    // Gracefully stop servers
    assert_eq!(oidc_tx.send(()), Ok(()));
    assert_eq!(db_tx.send(()), Ok(()));
    assert!(matches!(join!(oidc_handle, db_handle), ((), ())));
}

#[test]
fn run() {
    let example_dir = format!("{WORKSPACE_DIR}/tests/client/data/wasm_example");

    cmd!(
        fail: // when not specifying a wasm module
        "enarx run",
        text:
        "error: The following required arguments were not provided:
  <MODULE>

Usage: enarx run <MODULE>

For more information try '--help'"
    );

    // TODO: Get a better test.
    // Ideally the wasm example would print "Hello World" when no arguments are passed,
    // and otherwise read the passed-in arguments to say "Hello $FOO" for each argument.
    // This would let us better demonstrate configuration.
    cmd!(
        succeed: // when no configuration is given
        "enarx run {example_dir}/main.wasm",
        text:
        "Hello, world!"
    );

    cmd!(
        succeed: // when configuring via file
        "enarx run --wasmcfgfile {example_dir}/Enarx.toml {example_dir}/main.wasm",
        text:
        "Hello, world!"
    );

    cmd!(
        succeed: // when configuring via CLI
        r#"enarx run
        --with-files '[{{kind = "stdin"}}, {{kind = "stderr"}}, {{kind = "stderr"}}]'
        {example_dir}/main.wasm"#,
        text:
        "Hello, world!"
    );

    cmd!(
        succeed: // when configuring via file and overriding via CLI
        r#"enarx run
        --wasmcfgfile {example_dir}/Enarx.toml
        --with-files '[{{kind = "stdin"}}, {{kind = "stdin"}}, {{kind = "stdin"}}]'
        {example_dir}/main.wasm"#
    );
}

#[test]
fn config() {
    let tmpdir = Builder::new().prefix("test_config_init").tempdir().unwrap();
    env::set_current_dir(tmpdir.path()).unwrap();
    cmd!(succeed: "enarx config init");
    cmd!(fail: "enarx config init", text: r#"Error: "Enarx.toml" does already exist."#);
    assert!(Path::new("Enarx.toml").exists());
}
