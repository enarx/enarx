// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use walkdir::WalkDir;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const TEST_BINS_IN: &str = "tests/bin";

fn find_files_with_extensions<'a>(
    exts: &'a [&'a str],
    path: impl AsRef<Path>,
) -> impl Iterator<Item = PathBuf> + 'a {
    WalkDir::new(&path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(move |e| {
            e.path()
                .extension()
                .and_then(OsStr::to_str)
                .map(|ext| exts.contains(&ext))
                .unwrap_or(false)
        })
        .map(|x| x.path().to_owned())
}

fn rerun_src(path: impl AsRef<Path>) -> std::io::Result<()> {
    for entry in find_files_with_extensions(&["rs", "s", "S"], &path) {
        if let Some(path) = entry.to_str() {
            println!("cargo:rerun-if-changed={}", path)
        }
    }

    Ok(())
}

fn build_rs_tests(in_path: &Path, out_path: &Path) {
    let filtered_env: HashMap<String, String> = std::env::vars()
        .filter(|&(ref k, _)| {
            k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH" || k == "RUSTUP_HOME"
        })
        .collect();

    let target_name = "x86_64-unknown-linux-musl";

    for in_source in find_files_with_extensions(&["rs"], &in_path) {
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

        let output = in_source.file_stem().unwrap();

        let status = Command::new("rustc")
            .current_dir(&out_path)
            .env_clear()
            .envs(&filtered_env)
            .stdout(stdout)
            .stderr(stderr)
            .arg("-C")
            .arg("force-frame-pointers=yes")
            .arg("-C")
            .arg("debuginfo=2")
            .arg("--target")
            .arg(target_name)
            .arg(&in_source)
            .arg("-o")
            .arg(output)
            .status()
            .unwrap_or_else(|_| panic!("failed to compile {:#?}", &in_source));

        if !status.success() {
            panic!("Failed to compile {:?}", &in_source);
        }
    }
}

fn build_cc_tests(in_path: &Path, out_path: &Path) {
    for in_source in find_files_with_extensions(&["c", "s", "S"], &in_path) {
        let output = in_source.file_stem().unwrap();

        let mut cmd = cc::Build::new()
            .no_default_flags(true)
            .get_compiler()
            .to_command();

        let status = cmd
            .current_dir(&out_path)
            .arg("-nostdlib")
            .arg("-static-pie")
            .arg("-fPIC")
            .arg("-fno-omit-frame-pointer")
            .arg("-g")
            .arg("-o")
            .arg(output)
            .arg(&in_source)
            .status()
            .unwrap_or_else(|_| panic!("failed to compile {:#?}", &in_source));

        if !status.success() {
            panic!("Failed to compile {:?}", &in_source);
        }
    }
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

    build_cc_tests(&Path::new(CRATE).join(TEST_BINS_IN), &out_dir_bin);
    build_rs_tests(&Path::new(CRATE).join(TEST_BINS_IN), &out_dir_bin);

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

    // internal crates are not included, if there is a `Cargo.toml` file
    // trick cargo by renaming the `Cargo.toml` to `Cargo.tml` before
    // publishing and rename it back here.
    for entry in std::fs::read_dir("internal").unwrap() {
        let path = entry.unwrap().path();

        let cargo_toml = path.join("Cargo.toml");
        let cargo_tml = path.join("Cargo.tml");

        if cargo_tml.exists() {
            std::fs::copy(cargo_tml, cargo_toml).unwrap();
        }
    }

    for entry in std::fs::read_dir("internal").unwrap() {
        let path_buf = entry.unwrap().path();

        let shim_name = path_buf.clone();
        let shim_name = shim_name
            .file_name()
            .unwrap()
            .to_os_string()
            .into_string()
            .unwrap();

        let shim_out_dir = out_dir.join(&path_buf);

        let path: String = path_buf.into_os_string().into_string().unwrap();

        println!("cargo:rerun-if-changed={}/Cargo.tml", path);
        println!("cargo:rerun-if-changed={}/Cargo.toml", path);
        println!("cargo:rerun-if-changed={}/Cargo.lock", path);
        println!("cargo:rerun-if-changed={}/.cargo/config", path);

        rerun_src(&path).unwrap();

        if !shim_name.starts_with("shim-") {
            continue;
        }

        let target_dir = shim_out_dir.clone().into_os_string().into_string().unwrap();

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

        let status = Command::new("strip")
            .arg("--strip-unneeded")
            .arg("-o")
            .arg(&out_bin)
            .arg(&shim_out_bin)
            .status();

        match status {
            Ok(status) if status.success() => {}
            _ => {
                println!("cargo:warning=Failed to run `strip` on {:?}", &shim_out_bin);
                std::fs::rename(&shim_out_bin, &out_bin).expect("move failed")
            }
        }
    }
}
