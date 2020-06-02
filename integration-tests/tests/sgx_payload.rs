// SPDX-License-Identifier: Apache-2.0

//! This crate contains integration tests, including the SGX payload test.

#![deny(clippy::all)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Finds an absolute file path for a file in a directory.
#[cfg_attr(not(has_sgx), ignore)]
fn find_filepath(dir: PathBuf, name: &str) -> Result<PathBuf, std::io::Error> {
    let file = Command::new("find")
        .current_dir(&dir)
        .arg("-name")
        .arg(name)
        .output()
        .expect("could not find file")
        .stdout;

    let path = dir.join(String::from_utf8(file).unwrap().trim());
    Ok(std::fs::canonicalize(&path)?)
}

/// This test runs the payload in the SGX keep using the SGX shim.
#[cfg_attr(not(has_sgx), ignore)]
#[test]
fn sgx_payload() {
    // Define directories
    let wksp_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let sgx_keep_dir = wksp_root.join("enarx-keep-sgx/target/");
    let payload_dir = wksp_root.join("payload/target/x86_64-unknown-linux-musl/");
    let sgx_shim_dir = wksp_root.join("enarx-keep-sgx-shim/target/x86_64-unknown-linux-musl/");

    // Find the current SGX Keep, payload, and SGX shim
    let keep = find_filepath(sgx_keep_dir, "enarx-keep-sgx").unwrap();
    let payload = find_filepath(payload_dir, "payload").unwrap();
    let shim = find_filepath(sgx_shim_dir, "enarx-keep-sgx-shim").unwrap();

    // Run the test
    let mut payload_test = Command::new(keep)
        .current_dir(wksp_root)
        .arg("--code")
        .arg(payload)
        .arg("--shim")
        .arg(shim)
        .spawn()
        .expect("failed to run sgx payload test");

    let ecode = payload_test.wait().expect("failed to wait on child");

    assert!(ecode.success());
}
