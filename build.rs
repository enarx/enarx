// SPDX-License-Identifier: Apache-2.0

use std::env::var;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::fs::FileTypeExt;

fn generate_protos() {
    fn create(path: &Path) {
        match fs::create_dir(path) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                eprintln!("Can't create {path:#?} : {e:#?}");
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn host_has_sgx2() -> bool {
    use std::arch::x86_64::__cpuid;
    use std::os::unix::fs::PermissionsExt;

    Path::new("/dev/sgx_enclave").metadata().map_or(false, |m| {
        m.file_type().is_char_device() && m.permissions().mode() & 0o600 == 0o600
    }) && unsafe { __cpuid(0x7).ebx & (1 << 2) != 0 && __cpuid(0x12).eax & (1 << 1) != 0 }
}

fn main() {
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    // Enarx compilation target architecture and OS.
    // NOTE: This may or may not correspond to `target_os` and `target_arch` attributes,
    // since `build.rs` is compiled for the host triple and not the cargo compilation target
    let target_os = var("CARGO_CFG_TARGET_OS").expect("missing CARGO_CFG_TARGET_OS");
    let target_arch = var("CARGO_CFG_TARGET_ARCH").expect("missing CARGO_CFG_TARGET_ARCH");

    if target_os == "linux" && target_arch == "x86_64" {
        println!("cargo:rustc-cfg=enarx_with_shim");
    }
    if target_os == "linux" && target_arch == "x86_64" {
        generate_protos();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        if host_has_sgx2() {
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
