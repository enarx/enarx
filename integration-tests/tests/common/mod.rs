// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use wait_timeout::ChildExt;

#[cfg(has_sgx)]
const KEEP: &str = "enarx-keep-sgx";

#[cfg(has_sev)]
const KEEP: &str = "enarx-keep-sev";

#[cfg(not(any(has_sgx, has_sev)))]
const KEEP: &str = "";

#[cfg(has_sgx)]
const SHIM: &str = "enarx-keep-sgx-shim";

#[cfg(has_sev)]
const SHIM: &str = "enarx-keep-sev-shim";

#[cfg(not(any(has_sgx, has_sev)))]
const SHIM: &str = "";

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const PROFILE: &str = env!("PROFILE");

pub struct IntegrationTest {
    root: PathBuf,
    keep: PathBuf,
    shim: PathBuf,
    code: PathBuf,
}

impl IntegrationTest {
    pub fn new(bin: &str) -> Self {
        let crate_dir = Path::new(CRATE);

        let root = crate_dir.parent().unwrap().to_path_buf();

        let keep = root
            .join(KEEP)
            .join("target")
            .join(".") // Assume no target triple
            .join(PROFILE)
            .join(KEEP);

        let shim = root
            .join(SHIM)
            .join("target")
            .join("x86_64-unknown-linux-musl")
            .join(PROFILE)
            .join(SHIM);

        let code = crate_dir
            .join("target")
            .join("x86_64-unknown-linux-musl")
            .join(PROFILE)
            .join(bin);

        Self {
            root,
            keep,
            code,
            shim,
        }
    }

    pub fn run(self, timeout: u64, exit_status: i32) {
        let seconds = Duration::from_secs(timeout);

        let mut cmd = Command::new(self.keep)
            .current_dir(self.root)
            .arg("--code")
            .arg(self.code)
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
