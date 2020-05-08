// SPDX-License-Identifier: Apache-2.0

extern crate cc;
use std::ffi::OsString;
use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = manifest_dir.to_string_lossy();

    let mut asm_dir = PathBuf::from(manifest_dir.as_ref());
    asm_dir.push("asm");
    let entries = fs::read_dir(&asm_dir)
        .unwrap()
        .filter_map(|f| {
            f.ok().and_then(|e| {
                let path = e.path();
                match path.extension() {
                    Some(ext) if ext.eq(&OsString::from("c")) => Some(path),
                    Some(ext) if ext.eq(&OsString::from("s")) => Some(path),
                    Some(ext) if ext.eq(&OsString::from("S")) => Some(path),
                    _ => None,
                }
            })
        })
        .collect::<Vec<_>>();

    cc::Build::new()
        .no_default_flags(true)
        .flag("-O2")
        // Optimize for AMD Zen 2
        .flag("-mtune=znver2")
        .files(&entries)
        .static_flag(true)
        .shared_flag(false)
        .compile("asm");

    for e in entries {
        println!("cargo:rerun-if-changed={}", e.to_str().unwrap());
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=layout.ld");
}
