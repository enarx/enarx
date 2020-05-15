// SPDX-License-Identifier: Apache-2.0

extern crate cc;
use std::ffi::OsString;
use std::{env, path::PathBuf};
use walkdir::WalkDir;

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = manifest_dir.to_string_lossy();

    let mut src_dir = PathBuf::from(manifest_dir.as_ref());
    src_dir.push("src");

    let entries = WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(|f| {
            f.ok().and_then(|e| {
                let path = e.path();
                match path.extension() {
                    Some(ext) if ext.eq(&OsString::from("c")) => Some(e.into_path()),
                    Some(ext) if ext.eq(&OsString::from("s")) => Some(e.into_path()),
                    Some(ext) if ext.eq(&OsString::from("S")) => Some(e.into_path()),
                    _ => None,
                }
            })
        })
        .collect::<Vec<_>>();

    dbg!(&entries);
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
    println!("cargo:rerun-if-changed=link.json");
}
