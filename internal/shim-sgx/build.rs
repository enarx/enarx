// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rustc-link-arg-bin=shim-sgx=-Tlayout.ld");
    println!("cargo:rustc-link-arg-bin=shim-sgx=-Wl,--sort-section=alignment");
    println!("cargo:rustc-link-arg-bin=shim-sgx=-nostartfiles");
}
