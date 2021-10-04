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

fn rerun_src(path: impl AsRef<Path>) {
    for entry in find_files_with_extensions(&["rs", "s", "S"], &path) {
        if let Some(path) = entry.to_str() {
            println!("cargo:rerun-if-changed={}", path)
        }
    }
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

        assert!(status.success(), "Failed to compile {:?}", &in_source);
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

        assert!(status.success(), "Failed to compile {:?}", &in_source);
    }
}

#[cfg(feature = "wasmldr")]
fn build_wasm_tests(in_path: &Path, out_path: &Path) {
    for wat in find_files_with_extensions(&["wat"], &in_path) {
        let wasm = out_path
            .join(wat.file_stem().unwrap())
            .with_extension("wasm");
        let bin = wat::parse_file(&wat).unwrap_or_else(|_| panic!("failed to compile {:?}", &wat));
        std::fs::write(&wasm, &bin).unwrap_or_else(|_| panic!("failed to write {:?}", &wasm));
        println!("cargo:rerun-if-changed={}", &wat.display());
    }
}

// Build a binary named `bin_name` from the crate located at `in_dir`,
// targeting `target_name`, then strip the resulting binary and place it
// at `out_dir`/bin/`bin_name`.
fn cargo_build_bin(
    in_dir: &Path,
    out_dir: &Path,
    target_name: &str,
    bin_name: &str,
) -> std::io::Result<()> {
    let profile: &[&str] = match std::env::var("PROFILE").unwrap().as_str() {
        "release" => &["--release"],
        _ => &[],
    };

    let filtered_env: HashMap<String, String> = std::env::vars()
        .filter(|&(ref k, _)| {
            k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH" || k == "RUSTUP_HOME"
        })
        .collect();

    let path = in_dir.as_os_str().to_str().unwrap();

    println!("cargo:rerun-if-changed={}/Cargo.tml", path);
    println!("cargo:rerun-if-changed={}/Cargo.toml", path);
    println!("cargo:rerun-if-changed={}/Cargo.lock", path);
    println!("cargo:rerun-if-changed={}/layout.ld", path);
    println!("cargo:rerun-if-changed={}/.cargo/config", path);

    rerun_src(&path);

    let target_dir = out_dir.join(path);

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
        .arg(bin_name)
        .status()?;

    if !status.success() {
        eprintln!("Failed to build in {}", path);
        std::process::exit(1);
    }

    // This is the path to the newly-built binary.
    // See https://doc.rust-lang.org/cargo/guide/build-cache.html for details.
    let target_bin = target_dir
        .join(target_name)
        .join(std::env::var("PROFILE").unwrap())
        .join(bin_name);

    // And here's where we'd like to place the final (stripped) binary
    let out_bin = out_dir.join("bin").join(bin_name);

    // Strip the binary
    let status = Command::new("strip")
        .arg("--strip-unneeded")
        .arg("-o")
        .arg(&out_bin)
        .arg(&target_bin)
        .status()?;

    // Failing that, just copy it into place
    if !status.success() {
        println!("cargo:warning=Failed to run `strip` on {:?}", target_bin);
        std::fs::rename(&target_bin, &out_bin)?;
    }

    Ok(())
}

fn create(path: &Path) {
    match std::fs::create_dir(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            eprintln!("Can't create {:#?} : {:#?}", path, e);
            std::process::exit(1);
        }
        Ok(_) => {}
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let out_dir_proto = out_dir.join("protos");
    create(&out_dir_proto);

    protobuf_codegen_pure::Codegen::new()
        .out_dir(&out_dir_proto)
        .inputs(&["src/protobuf/aesm-proto.proto"])
        .include("src/protobuf")
        .customize(protobuf_codegen_pure::Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .run()
        .expect("Protobuf codegen failed");

    let out_dir_bin = out_dir.join("bin");
    create(&out_dir_bin);

    build_cc_tests(&Path::new(CRATE).join(TEST_BINS_IN), &out_dir_bin);
    build_rs_tests(&Path::new(CRATE).join(TEST_BINS_IN), &out_dir_bin);
    #[cfg(feature = "wasmldr")]
    build_wasm_tests(&Path::new(CRATE).join("tests/wasm"), &out_dir_bin);

    let target = "x86_64-unknown-linux-musl";

    // internal crates are not included, if there is a `Cargo.toml` file
    // trick cargo by renaming the `Cargo.toml` to `Cargo.tml` before
    // publishing and rename it back here.
    for entry in std::fs::read_dir("internal")? {
        let path = entry?.path();

        let cargo_toml = path.join("Cargo.toml");
        let cargo_tml = path.join("Cargo.tml");

        if cargo_tml.exists() {
            std::fs::copy(cargo_tml, cargo_toml)?;
        }

        let dir_name = path.file_name().unwrap().to_str().unwrap_or_default();

        match dir_name {
            #[cfg(feature = "wasmldr")]
            "wasmldr" => cargo_build_bin(&path, &out_dir, target, "wasmldr")?,

            #[cfg(feature = "backend-kvm")]
            "shim-sev" => cargo_build_bin(&path, &out_dir, target, "shim-sev")?,

            #[cfg(feature = "backend-sgx")]
            "shim-sgx" => cargo_build_bin(&path, &out_dir, target, "shim-sgx")?,

            _ => continue,
        }
    }

    Ok(())
}
