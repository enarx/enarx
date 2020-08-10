// SPDX-License-Identifier: Apache-2.0
fn main() {}
/*
use std::path::Path;

fn main() {
    let in_dir = Path::new("fixtures");
    let out_dir =
        std::env::var_os("OUT_DIR").expect("The OUT_DIR environment variable must be set");
    let out_dir = Path::new(&out_dir).join("fixtures");
    std::fs::create_dir_all(&out_dir).expect("Can't create output directory");

    for entry in in_dir.read_dir().unwrap() {
        if let Ok(entry) = entry {
            let wat = entry.path();
            if wat.extension().unwrap() == "wat" {
                let wasm = out_dir
                    .join(wat.file_name().unwrap())
                    .with_extension("wasm");
                let binary = wat::parse_file(&wat).expect("Can't parse wat file");
                std::fs::write(wasm, &binary).expect("Can't write wasm file");
                println!("cargo:rerun-if-changed={}", &wat.display());
            }
        }
    }
}
*/
