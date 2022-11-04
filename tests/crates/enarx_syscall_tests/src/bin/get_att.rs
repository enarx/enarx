// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    if !is_enarx() {
        Ok(())
    } else {
        get_att(None, None)?;

        Ok(())
    }
}
