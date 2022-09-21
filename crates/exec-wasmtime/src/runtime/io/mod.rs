// SPDX-License-Identifier: Apache-2.0

//! I/O functionality for keeps

pub mod null;

use wasi_common::file::FileCaps;
use wasi_common::WasiFile;

pub fn stdio_file(mut file: impl WasiFile + 'static) -> (Box<dyn WasiFile>, FileCaps) {
    // Ensure wasmtime can detect the TTY.
    let caps = if file.isatty() {
        FileCaps::all().difference(FileCaps::TELL | FileCaps::SEEK)
    } else {
        FileCaps::all()
    };
    (Box::new(file), caps)
}
