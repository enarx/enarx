// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!(
        "cargo:rustc-link-arg-bin=enarx-shim-kvm=-T{}/layout.ld",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg-bin=enarx-shim-kvm=-Wl,--sort-section=alignment");
    println!("cargo:rustc-link-arg-bin=enarx-shim-kvm=-nostartfiles");
}
