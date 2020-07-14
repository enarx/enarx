// SPDX-License-Identifier: Apache-2.0

use libc::write;

fn main() {
    let buf = "hello world\n";
    unsafe {
        write(libc::STDOUT_FILENO, buf.as_ptr() as *const _, buf.len());
    }
}
