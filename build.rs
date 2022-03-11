// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use walkdir::WalkDir;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const TEST_BINS_IN: &str = "tests/c-tests";

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
        if let Some(Some(path)) = entry.parent().map(Path::to_str) {
            println!("cargo:rerun-if-changed={}", path)
        }
    }
}

fn build_cc_tests(in_path: &Path, out_path: &Path) {
    for in_source in find_files_with_extensions(&["c", "s", "S"], &in_path) {
        if let Some(path) = in_source.to_str() {
            println!("cargo:rerun-if-changed={}", path)
        }
        if let Some(Some(path)) = in_source.parent().map(Path::to_str) {
            println!("cargo:rerun-if-changed={}", path)
        }

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
            .arg("-fno-stack-protector")
            .arg("-g")
            .arg("-o")
            .arg(output)
            .arg(&in_source)
            .status()
            .unwrap_or_else(|_| panic!("failed to compile {:#?}", &in_source));

        assert!(status.success(), "Failed to compile {:?}", &in_source);
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
    // And here's where we'd like to place the final (stripped) binary
    let out_bin = out_dir.join("bin").join(bin_name);

    // Don't run the build if ENARX_PREBUILT_${bin_name} is set
    let prebuilt_env_name = format!("ENARX_PREBUILT_{}", bin_name);
    if let Ok(prebuilt_path) = std::env::var(&prebuilt_env_name) {
        println!(
            "cargo:warning=Using prebuilt {} binary from {}: {}",
            bin_name, prebuilt_env_name, &prebuilt_path
        );
        std::fs::copy(prebuilt_path, out_bin)?;
        return Ok(());
    }

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

    for p in [
        "src",
        "tests",
        "build.rs",
        "Cargo.tml",
        "Cargo.toml",
        "Cargo.lock",
        "layout.ld",
        ".cargo",
        ".cargo/config",
    ] {
        let file = in_dir.join(p);
        if file.exists() {
            println!("cargo:rerun-if-changed={}/{}", path, p);
        }
    }

    rerun_src(&path);

    let target_dir = out_dir.join(path);

    let stdout: Stdio = fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::inherit());

    let stderr: Stdio = fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::inherit());

    let mut cmd = Command::new("cargo");
    let cmd = cmd
        .current_dir(&path)
        .env_clear()
        .envs(&filtered_env)
        .stdout(stdout)
        .stderr(stderr)
        .arg("build")
        .args(profile)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--target")
        .arg(target_name)
        .arg("--bin")
        .arg(bin_name);

    #[cfg(feature = "gdb")]
    let cmd = cmd.arg("--features=gdb");

    #[cfg(feature = "dbg")]
    let cmd = cmd.arg("--features=dbg");

    let status = cmd.status()?;

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

fn main() {
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

    let target = "x86_64-unknown-linux-musl";

    // internal crates are not included, if there is a `Cargo.toml` file
    // trick cargo by renaming the `Cargo.toml` to `Cargo.tml` before
    // publishing and rename it back here.
    for entry in std::fs::read_dir("internal").unwrap() {
        let path = entry.unwrap().path();

        let cargo_toml = path.join("Cargo.toml");
        let cargo_tml = path.join("Cargo.tml");

        if cargo_tml.exists() {
            std::fs::copy(&cargo_tml, &cargo_toml).unwrap();
        }

        let dir_name = path.file_name().unwrap().to_str().unwrap_or_default();

        match dir_name {
            #[cfg(feature = "wasmldr")]
            "wasmldr" => cargo_build_bin(&path, &out_dir, target, "wasmldr").unwrap(),

            #[cfg(feature = "backend-kvm")]
            "shim-kvm" => cargo_build_bin(&path, &out_dir, target, "shim-kvm").unwrap(),

            #[cfg(feature = "backend-sgx")]
            "shim-sgx" => cargo_build_bin(&path, &out_dir, target, "shim-sgx").unwrap(),

            _ => eprintln!("Unknown internal directory: {}", dir_name),
        }

        if cargo_tml.exists() {
            std::fs::remove_file(&cargo_toml).unwrap()
        }
    }

    if std::path::Path::new("/dev/sgx_enclave").exists() {
        // Not expected to fail, as the file exists.
        let metadata = fs::metadata("/dev/sgx_enclave").unwrap();
        let file_type = metadata.file_type();

        if file_type.is_char_device() {
            println!("cargo:rustc-cfg=host_can_test_sgx");
        }
    }

    if std::path::Path::new("/dev/sev").exists() {
        // Not expected to fail, as the file exists.
        let metadata = fs::metadata("/dev/sev").unwrap();
        let file_type = metadata.file_type();

        if file_type.is_char_device() {
            println!("cargo:rustc-cfg=host_can_test_sev");
        }
    }
}
