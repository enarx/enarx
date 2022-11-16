// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]

enarx_syscall_tests::startup!();

fn main() -> enarx_syscall_tests::Result<()> {
    Err(1)
}
