// SPDX-License-Identifier: Apache-2.0

use libc::{read, write, STDIN_FILENO as IN, STDOUT_FILENO as OUT};
use std::cmp::min;
use std::process::exit;

fn main() {
    let mut buf = [0u8; 16];
    let mut len = 1;

    loop {
        match unsafe { read(IN, buf.as_mut_ptr() as *mut _, len) } {
            sz if sz > 0 => unsafe {
                write(OUT, buf.as_ptr() as *const _, sz as usize);
            },
            sz if sz < 0 => exit(1),
            _ => break,
        }

        len = min(len * 2, buf.len());
    }
}
