// SPDX-License-Identifier: Apache-2.0
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const TEST_BINS_IN: &str = "tests/c-tests";
const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

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

    // FIXME: this exists to work around https://github.com/rust-lang/cargo/issues/10527
    println!("cargo:rerun-if-changed=src/bin");

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

    if std::path::Path::new("/dev/sgx_enclave").exists()
        && fs::metadata("/dev/sgx_enclave")
            .unwrap()
            .file_type()
            .is_char_device()
    {
        println!("cargo:rustc-cfg=host_can_test_sgx");

        if (!cfg!(feature = "disable-sgx-attestation"))
            && std::path::Path::new(AESM_SOCKET).exists()
            && fs::metadata(AESM_SOCKET).unwrap().file_type().is_socket()
        {
            println!("cargo:rustc-cfg=host_can_test_attestation");
        }
    }

    if std::path::Path::new("/dev/sev").exists() {
        // Not expected to fail, as the file exists.
        let metadata = fs::metadata("/dev/sev").unwrap();
        let file_type = metadata.file_type();

        if file_type.is_char_device() {
            println!("cargo:rustc-cfg=host_can_test_sev");
            println!("cargo:rustc-cfg=host_can_test_attestation");
        }
    }
}
