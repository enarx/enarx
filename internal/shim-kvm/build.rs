// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rustc-link-arg-bin=shim-kvm=-Tlayout.ld");
    println!("cargo:rustc-link-arg-bin=shim-kvm=-Wl,--sort-section=alignment");
    println!("cargo:rustc-link-arg-bin=shim-kvm=-nostartfiles");
}
