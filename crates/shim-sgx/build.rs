// SPDX-License-Identifier: Apache-2.0

use std::env::var;

fn main() {
    if var("CARGO_CFG_TARGET_OS").expect("missing CARGO_CFG_TARGET_OS") == "none" {
        println!(
            "cargo:rustc-link-arg-bin=enarx-shim-sgx=-T{}/layout.ld",
            var("CARGO_MANIFEST_DIR").unwrap()
        );
        println!("cargo:rustc-link-arg-bin=enarx-shim-sgx=-Wl,--sort-section=alignment");
        println!("cargo:rustc-link-arg-bin=enarx-shim-sgx=-Wl,-z,max-page-size=4096");
        println!("cargo:rustc-link-arg-bin=enarx-shim-sgx=-nostartfiles");
    }
}
