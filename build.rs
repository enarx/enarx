// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

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
    println!("cargo:rerun-if-changed=crates/");

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
