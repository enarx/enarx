// SPDX-License-Identifier: Apache-2.0

use std::env::var;

fn main() {
    if var("CARGO_CFG_TARGET_OS").expect("missing CARGO_CFG_TARGET_OS") == "none" {
        println!("cargo:rustc-link-arg=-nostartfiles");
        println!("cargo:rustc-link-arg=-static-pie");
    }
}
