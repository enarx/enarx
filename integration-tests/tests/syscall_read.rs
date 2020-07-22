// SPDX-License-Identifier: Apache-2.0

//! This crate contains integration tests, including the exit syscall payload test.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod common;
use common::IntegrationTest;

/// This test runs the read syscall payload in the SGX keep using the SGX shim.
#[test]
#[cfg_attr(not(any(has_sgx, has_sev)), ignore)]
fn read() {
    IntegrationTest::new("read").run(5, 0, "hello world\n", "hello world\n", "");
}

#[test]
#[should_panic]
#[cfg_attr(not(any(has_sgx, has_sev)), ignore)]
fn read_with_wrong_output() {
    IntegrationTest::new("read").run(5, 0, "hello", "h", "");
}
