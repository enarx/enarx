// SPDX-License-Identifier: Apache-2.0

fn main() {
    cc::Build::new().file("src/start.s").compile("start");

    // Re-run this build script on linker changes.
    println!("cargo:rerun-if-changed=link.json");
    println!("cargo:rerun-if-changed=layout.ld");

    // Touch the main file to rebuild due to link.json changes.
    std::fs::OpenOptions::new()
        .append(true)
        .open("src/main.rs")
        .unwrap();
}
