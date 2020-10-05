// SPDX-License-Identifier: Apache-2.0

fn main() {
    cc::Build::new().file("src/start.S").compile("asm");

    // Re-run this build script on assembly changes.
    println!("cargo:rerun-if-changed=src/start.S");
}
