// SPDX-License-Identifier: Apache-2.0

// Author: Mike Bursell <mike@profian.com>
// https://github.com/MikeCamel/zerooneone/

use std::io::{stdin, stdout, Read, Result, Write};

const INPUT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const OUTPUT: &[u8] = b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm";

fn main() -> Result<()> {
    let std_in = stdin();
    let mut std_out = stdout();

    for result in std_in.bytes() {
        let input = result?;

        // If the input is in the Latin alphabet, do ROT13.
        // Otherwise, output the input unmodified.
        let output = match INPUT.iter().position(|b| b == &input) {
            Some(index) => OUTPUT[index],
            None => input,
        };

        std_out.write_all(&[output])?;
    }

    Ok(())
}
