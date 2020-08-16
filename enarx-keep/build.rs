// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

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

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let profile: &[&str] = match std::env::var("PROFILE").unwrap().as_str() {
        "debug" => &["--debug"],
        _ => &[],
    };

    for entry in std::fs::read_dir("shims").unwrap() {
        let path: String = entry
            .unwrap()
            .path()
            .into_os_string()
            .into_string()
            .unwrap();

        println!("cargo:rerun-if-changed={}/Cargo.toml", path);
        println!("cargo:rerun-if-changed={}/Cargo.lock", path);
        println!("cargo:rerun-if-changed={}/link.json", path);
        rerun_src(&path).unwrap();

        Command::new("cargo")
            .arg("install")
            .args(profile)
            .arg("--path")
            .arg(&path)
            .arg("--root")
            .arg(&out_dir)
            .status()
            .expect("failed to build shim");
    }
}
