// SPDX-License-Identifier: Apache-2.0

fn main() {
    cc::Build::new().file("src/lib.s").compile("asm");
    println!("cargo:rerun-if-changed=src/lib.s");
}
