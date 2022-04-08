// SPDX-License-Identifier: Apache-2.0

#![feature(core_ffi_c)]

use rust_exec_tests::musl_fsbase_fix;
use std::io::{self, Read, Write};

musl_fsbase_fix!();

fn main() -> io::Result<()> {
    let mut buffer = Vec::new();
    std::io::stdin().read_to_end(&mut buffer)?;
    std::io::stdout().write_all(&buffer)?;
    Ok(())
}
