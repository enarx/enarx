// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rustc-link-arg-bin=shim-kvm=-Tlayout.ld");
    println!("cargo:rustc-link-arg-bin=shim-kvm=--sort-section=alignment");
    println!("cargo:rerun-if-changed=layout.ld");
}
