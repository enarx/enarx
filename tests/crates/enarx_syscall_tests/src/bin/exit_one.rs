// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

enarx_syscall_tests::startup!();

fn main() -> enarx_syscall_tests::Result<()> {
    Err(1)
}
