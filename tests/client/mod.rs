// SPDX-License-Identifier: Apache-2.0

mod util;

use util::{enarx, run};

use std::env;
use std::path::Path;

use tempfile::Builder;

/// Just a nice wrapper over `format!` for testing CLI invocations
macro_rules! cmd {
    ($($arg:tt)+) => (
        enarx(format!($($arg)+))
    )
}

#[async_std::test]
async fn full() {
    run(|oidc_addr, db_addr| {
        let workspace_dir = env!("CARGO_MANIFEST_DIR");

        env::set_var("ENARX_CA_BUNDLE", format!("{workspace_dir}/tests/client/testdata/ca.crt"));
        env::set_var("ENARX_INSECURE_AUTH_TOKEN", "test-token");

        // test for failure when looking up a user that does not exist
        let cmd = cmd!("enarx user info {db_addr}/testuser");
        assert_eq!(cmd.success, false);

        // test for failure when registering user without proper credentials
        let cmd = cmd!(
            "enarx user register
            --insecure_auth_token bad-token
            --oidc-domain {oidc_addr}
            --oidc-client-id test-client-id
            {db_addr}/testuser"
        );
        assert_eq!(cmd.success, false);

        // test for success when registering user with proper credentials
        let cmd = cmd!(
            "enarx user register
            --oidc-domain {oidc_addr}
            --oidc-client-id test-client-id
            {db_addr}/testuser"
        );
        assert_eq!(cmd.success, true);

        // test for failure when creating a user whose subject matches an existing user
        let cmd = cmd!(
            "enarx user register
            --oidc-domain {oidc_addr}
            --oidc-client-id test-client-id
            {db_addr}/testuser2"
        );
        assert_eq!(cmd.success, false);

        // test for success when looking up a user that exists
        let cmd = cmd!("enarx user info {db_addr}/testuser");
        assert_eq!(cmd.output, "{\n  \"subject\": \"test|subject\"\n}\n");

        // test for failure when looking up a repo that does not exist
        let cmd = cmd!("enarx repo info {db_addr}/testuser/publicrepo");
        assert_eq!(cmd.success, false);

        // test for success when registering a public repo
        let cmd = cmd!("enarx repo register {db_addr}/testuser/publicrepo");
        assert_eq!(cmd.success, true);

        // test for success when fetching tags from empty public repo
        let cmd = cmd!("enarx repo info {db_addr}/testuser/publicrepo");
        assert_eq!(cmd.output, "{\n  \"config\": {\n    \"public\": true\n  },\n  \"tags\": []\n}\n");

        // test for failure when looking up a package that does not exist
        let cmd = cmd!("enarx package info {db_addr}/testuser/publicrepo:0.1.0");
        assert_eq!(cmd.success, false);

        // test for failure when publishing an invalid file as a public package
        let cmd = cmd!(
            "enarx package publish
            {db_addr}/testuser/publicrepo:0.0.0
            {workspace_dir}/tests/client/testdata/generate.sh"
        );
        assert_eq!(cmd.success, false);

        // test for failure when publishing an invalid directory as a public package
        let cmd = cmd!(
            "enarx package publish
            {db_addr}/testuser/publicrepo:0.0.0
            {workspace_dir}/tests/client/testdata"
        );
        assert_eq!(cmd.success, false);

        // test for success when publishing a main.wasm file as a public package
        let cmd = cmd!(
            "enarx package publish
            {db_addr}/testuser/publicrepo:1.0.0
            {workspace_dir}/tests/client/testdata/wasm_example/main.wasm"
        );
        assert_eq!(cmd.success, true);

        // test for success when publishing a directory as a public package
        let cmd = cmd!(
            "enarx package publish
            {db_addr}/testuser/publicrepo:2.0.0
            {workspace_dir}/tests/client/testdata/wasm_example"
        );
        assert_eq!(cmd.success, true);

        // test for success when looking up a public package that exists
        let cmd = cmd!("enarx package info {db_addr}/testuser/publicrepo:2.0.0");
        assert_eq!(cmd.output, "{\n  \"digest\": {\n    \"sha-224\": \"9lthJYmqbXNwwWIK5CYHYnfBkqhz71mIWO6Vjw==\",\n    \"sha-256\": \"c/MsTz6fW1Y2eqnSDhGqmoOyyvTL5W7EOJJ6FpdlEzo=\",\n    \"sha-384\": \"DGIbID9HBhO2zqIH9fMlknguUCxau60fxpC/kb4sBy1xb5GcseHmtjsBUwA6Vfj3\",\n    \"sha-512\": \"RRXxD15/IUm/2WWUG58Erg4wtF5LHE3urhKsB8+H2IBOLnLApcXtinUA7dO+JshfP7DBWIJ+QhjjwzYyRlI5+A==\"\n  },\n  \"length\": 709,\n  \"type\": \"application/vnd.drawbridge.directory.v1+json\"\n}\n");

        // test for success when fetching tags from a non-empty public repo
        let cmd = cmd!("enarx repo info {db_addr}/testuser/publicrepo");
        assert_eq!(cmd.success, true);

        // TODO: fetch package
        // TODO: deploy package
    })
    .await;
}

#[test]
fn test_config_init() {
    let tmpdir = Builder::new().prefix("test_config_init").tempdir().unwrap();
    env::set_current_dir(tmpdir.path()).unwrap();
    let cmd = cmd!("enarx config init");
    assert_eq!(cmd.success, true);
    let cmd = cmd!("enarx config init");
    assert_eq!(cmd.success, false);
    assert_eq!(Path::new("Enarx.toml").exists(), true);
}
