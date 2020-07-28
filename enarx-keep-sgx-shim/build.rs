// SPDX-License-Identifier: Apache-2.0

fn main() {
    cc::Build::new().file("src/start.S").compile("asm");

    // Re-run this build script on assembly changes.
    println!("cargo:rerun-if-changed=src/start.S");

    // Re-run this build script on linker changes.
    println!("cargo:rerun-if-changed=link.json");

    // Touch the main file to rebuild due to link.json changes.
    std::fs::OpenOptions::new()
        .append(true)
        .open("src/main.rs")
        .unwrap();
}
