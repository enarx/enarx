// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut buffer = Vec::new();
    std::io::stdin().read_to_end(&mut buffer)?;
    std::io::stdout().write_all(&buffer)?;
    Ok(())
}
