// SPDX-License-Identifier: Apache-2.0

//! I/O functionality for keeps

pub mod null;

use wasi_common::file::FileAccessMode;
use wasi_common::WasiFile;

// This import provides the trait needed for `FileAccessMode::all()`, yet Clippy
// claims the import isn't used. Remove this import and the code fails to compile!
#[allow(unused_imports)]
use wiggle::bitflags::Flags;

pub fn stdio_file(mut file: impl WasiFile + 'static) -> (Box<dyn WasiFile>, FileAccessMode) {
    // Ensure wasmtime can detect the TTY.
    let mode = if file.isatty() {
        FileAccessMode::all()
    } else {
        FileAccessMode::READ
    };
    (Box::new(file), mode)
}
