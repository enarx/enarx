// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::Lazy;
use std::env::var;
use std::fs;
use std::path::{Path, PathBuf};

/// Whether Enarx compilation target is x86_64 Linux or not.
// NOTE: This may or may not correspond to `target_os` and `target_arch`, since `build.rs` is
// compiled for the host triple and not the cargo compilation target
static IS_X86_64_LINUX: Lazy<bool> = Lazy::new(|| {
    var("CARGO_CFG_TARGET_OS").expect("missing CARGO_CFG_TARGET_OS") == "linux"
        && var("CARGO_CFG_TARGET_ARCH").expect("missing CARGO_CFG_TARGET_ARCH") == "x86_64"
});

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::fs::FileTypeExt;

fn generate_protos() {
    fn create(path: &Path) {
        match fs::create_dir(path) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                eprintln!("Can't create {:#?} : {:#?}", path, e);
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }

    let out_dir = PathBuf::from(var("OUT_DIR").unwrap());
    let out_dir_proto = out_dir.join("protos");
    create(&out_dir_proto);

    protobuf_codegen_pure::Codegen::new()
        .out_dir(&out_dir_proto)
        .inputs(["src/protobuf/aesm-proto.proto"])
        .include("src/protobuf")
        .customize(protobuf_codegen_pure::Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .run()
        .expect("Protobuf codegen failed");
}

fn main() {
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    // FIXME: this exists to work around https://github.com/rust-lang/cargo/issues/10527
    println!("cargo:rerun-if-changed=crates/");

    if *IS_X86_64_LINUX {
        println!("cargo:rustc-cfg=enarx_with_shim");
    }

    if *IS_X86_64_LINUX {
        generate_protos();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        if Path::new("/dev/sgx_enclave").exists()
            && fs::metadata("/dev/sgx_enclave")
                .unwrap()
                .file_type()
                .is_char_device()
        {
            const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

            println!("cargo:rustc-cfg=host_can_test_sgx");

            if (!cfg!(feature = "disable-sgx-attestation"))
                && Path::new(AESM_SOCKET).exists()
                && fs::metadata(AESM_SOCKET).unwrap().file_type().is_socket()
            {
                println!("cargo:rustc-cfg=host_can_test_attestation");
            }
        }

        if Path::new("/dev/sev").exists() {
            // Not expected to fail, as the file exists.
            let metadata = fs::metadata("/dev/sev").unwrap();
            let file_type = metadata.file_type();

            if file_type.is_char_device() {
                println!("cargo:rustc-cfg=host_can_test_sev");
                println!("cargo:rustc-cfg=host_can_test_attestation");
            }
        }

        if Path::new("/dev/kvm").exists() {
            println!("cargo:rustc-cfg=host_can_test_kvm");
        }
    }
}
