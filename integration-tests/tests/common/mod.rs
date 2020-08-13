// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const PROFILE: &str = env!("PROFILE");

pub struct IntegrationTest {
    root: PathBuf,
    keep: PathBuf,
    code: PathBuf,
}

impl IntegrationTest {
    pub fn new(bin: &str) -> Self {
        let crate_dir = Path::new(CRATE);

        let root = crate_dir.parent().unwrap().to_path_buf();

        let keep = root
            .join("enarx-keep")
            .join("target")
            .join(".") // Assume no target triple
            .join(PROFILE)
            .join("enarx-keep");

        let code = crate_dir
            .join("target")
            .join("x86_64-unknown-linux-musl")
            .join(PROFILE)
            .join(bin);

        Self { root, keep, code }
    }

    pub fn run(
        self,
        timeout: u64,
        exit_status: i32,
        stdin: impl AsRef<[u8]>,
        stdout: impl AsRef<[u8]>,
        stderr: impl AsRef<[u8]>,
    ) {
        let seconds = Duration::from_secs(timeout);

        let mut cmd = Command::new(self.keep)
            .current_dir(self.root)
            .arg("exec")
            .arg(self.code)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to run the test");

        cmd.stdin
            .as_mut()
            .unwrap()
            .write_all(stdin.as_ref())
            .expect("Failed to write stdin");
        let ecode = match cmd.wait_timeout(seconds).unwrap() {
            Some(status) => status.code(),
            None => {
                cmd.kill().unwrap();
                panic!("killed by watchdog!");
            }
        };
        let output = cmd
            .wait_with_output()
            .expect("Failed to read stdout/stderr");

        assert_stdio(stdout, output.stdout);
        assert_stdio(stderr, output.stderr);
        assert_eq!(exit_status, ecode.unwrap());
    }
}

fn assert_stdio(lhs: impl AsRef<[u8]>, rhs: impl AsRef<[u8]>) {
    let lhs_str = String::from_utf8_lossy(lhs.as_ref());
    let rhs_str = String::from_utf8_lossy(rhs.as_ref());
    assert_eq!(
        lhs.as_ref(),
        rhs.as_ref(),
        "\n\nEXPECTED:\n\n{}\n\nGIVEN\n\n{}\n\n",
        lhs_str,
        rhs_str
    );
}
