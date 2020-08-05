// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!(
        "cargo:rustc-env=PROFILE={}",
        std::env::var("PROFILE").unwrap()
    );

    if std::path::Path::new("/dev/sgx/enclave").exists() {
        println!("cargo:rustc-cfg=has_sgx");
    } else if std::path::Path::new("/dev/kvm").exists() {
        println!("cargo:rustc-cfg=has_kvm");
    }
}
