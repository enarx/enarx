// SPDX-License-Identifier: Apache-2.0

//! This crate contains the common code for integration tests

#![deny(clippy::all)]
#![deny(missing_docs)]

use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use wait_timeout::ChildExt;
use walkdir::WalkDir;

pub fn keep_type() -> &'static str {
    #[cfg(has_sgx)]
    return "enarx-keep-sgx";

    #[cfg(has_sev)]
    return "enarx-keep-sev";

    #[cfg(not(any(has_sgx, has_sev)))]
    compile_error!("Need either SGX or SEV!");
}

pub struct IntegrationTest {
    pub wksp_root: PathBuf,
    pub keep: PathBuf,
    pub payload: PathBuf,
    pub shim: PathBuf,
}

impl IntegrationTest {
    pub fn new(bin: &str) -> Self {
        let enarx_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let enarx_dir = enarx_dir.parent().unwrap();
        let keep_type = keep_type();

        let wksp_root = enarx_dir.to_path_buf();
        let keep_dir = enarx_dir
            .join(format!("{}/target/", keep_type))
            .to_path_buf();
        let payload_dir = enarx_dir
            .join("integration-tests/target/x86_64-unknown-linux-musl/")
            .to_path_buf();
        let shim_dir = enarx_dir
            .join(format!(
                "{}-shim/target/x86_64-unknown-linux-musl/",
                keep_type
            ))
            .to_path_buf();
        let shim_filename = format!("{}-shim", keep_type);
        let shim_filename = shim_filename.as_str();

        let keep = find_filepath(keep_dir, keep_type).unwrap();
        let payload = find_filepath(payload_dir, bin).unwrap();
        let shim = find_filepath(shim_dir, shim_filename).unwrap();

        Self {
            wksp_root,
            keep,
            payload,
            shim,
        }
    }

    pub fn run(self: Self, timeout: u64, exit_status: i32) -> () {
        let seconds = Duration::from_secs(timeout);

        let mut cmd = Command::new(self.keep)
            .current_dir(self.wksp_root)
            .arg("--code")
            .arg(self.payload)
            .arg("--shim")
            .arg(self.shim)
            .spawn()
            .expect("failed to run the test");

        let ecode = match cmd.wait_timeout(seconds).unwrap() {
            Some(status) => status.code(),
            None => {
                cmd.kill().unwrap();
                panic!("killed by watchdog!");
            }
        };

        assert_eq!(exit_status, ecode.unwrap());
    }
}

/// Finds an absolute file path for a file in a directory.
#[cfg_attr(not(has_sgx), ignore)]
pub fn find_filepath(dir: impl AsRef<Path>, name: &str) -> Result<PathBuf, Error> {
    for entry in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().file_name().unwrap() == name {
            return Ok(entry.path().to_path_buf());
        }
    }
    Err(Error::new(ErrorKind::Other, "file not found"))
}
