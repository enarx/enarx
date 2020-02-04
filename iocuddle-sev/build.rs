// SPDX-License-Identifier: Apache-2.0

fn main() {
    use std::path::Path;

    if Path::new("/dev/sev").exists() {
        println!("cargo:rustc-cfg=has_sev");
    }
}
