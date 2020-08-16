// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rerun_src(path: impl AsRef<Path>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let path = entry?.path();

        if path.is_dir() {
            rerun_src(path)?;
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                if let Some(ext) = ext.to_str() {
                    if let Some(path) = path.to_str() {
                        match ext {
                            "rs" => println!("cargo:rerun-if-changed={}", path),
                            "s" => println!("cargo:rerun-if-changed={}", path),
                            "S" => println!("cargo:rerun-if-changed={}", path),
                            _ => (),
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() {
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let out_dir_bin = out_dir.join("bin");

    match std::fs::create_dir(&out_dir_bin) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            eprintln!("Can't create {:#?} : {:#?}", out_dir_bin, e);
            std::process::exit(1);
        }
        Ok(_) => {}
    }

    let profile: &[&str] = match std::env::var("PROFILE").unwrap().as_str() {
        "release" => &["--release"],
        _ => &[],
    };

    let target_name = "x86_64-unknown-linux-musl";

    let filtered_env: HashMap<String, String> = std::env::vars()
        .filter(|&(ref k, _)| {
            k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH" || k == "RUSTUP_HOME"
        })
        .collect();

    for entry in std::fs::read_dir("shims").unwrap() {
        let shim_path = entry.unwrap().path();
        let shim_name = shim_path.clone();
        let shim_name = shim_name
            .file_name()
            .unwrap()
            .to_os_string()
            .into_string()
            .unwrap();

        let shim_out_dir = out_dir.join(&shim_path);

        let target_dir = shim_out_dir.clone().into_os_string().into_string().unwrap();

        let path: String = shim_path.into_os_string().into_string().unwrap();

        println!("cargo:rerun-if-changed={}/Cargo.toml", path);
        println!("cargo:rerun-if-changed={}/Cargo.lock", path);
        println!("cargo:rerun-if-changed={}/link.json", path);
        println!("cargo:rerun-if-changed={}/.cargo/config", path);
        rerun_src(&path).unwrap();

        let stdout: Stdio = OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::inherit());

        let stderr: Stdio = OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::inherit());

        let status = Command::new("cargo")
            .current_dir(&path)
            .env_clear()
            .envs(&filtered_env)
            .stdout(stdout)
            .stderr(stderr)
            .arg("+nightly")
            .arg("build")
            .args(profile)
            .arg("--target-dir")
            .arg(&target_dir)
            .arg("--target")
            .arg(target_name)
            .arg("--bin")
            .arg(&shim_name)
            .status()
            .expect("failed to build shim");

        if !status.success() {
            eprintln!("Failed to build shim {}", path);
            std::process::exit(1);
        }

        let out_bin = out_dir_bin.join(&shim_name);

        let shim_out_bin = shim_out_dir
            .join(&target_name)
            .join(&std::env::var("PROFILE").unwrap())
            .join(&shim_name);

        std::fs::rename(&shim_out_bin, &out_bin).expect("move failed");
    }
}
