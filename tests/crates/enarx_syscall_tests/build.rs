// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rustc-link-arg=-static-pie");
}
