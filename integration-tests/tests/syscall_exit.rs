// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod common;
use common::IntegrationTest;

#[test]
#[cfg_attr(not(any(has_sgx, has_sev)), ignore)]
fn exit_zero() {
    IntegrationTest::new("exit_zero").run(5, 0, "", "", "");
}

#[test]
#[should_panic]
#[cfg_attr(not(any(has_sgx, has_sev)), ignore)]
fn watchdog() {
    IntegrationTest::new("watchdog").run(5, 0, "", "", "");
}

#[test]
#[cfg_attr(not(any(has_sgx, has_sev)), ignore)]
fn exit_one() {
    IntegrationTest::new("exit_one").run(5, 1, "", "", "");
}
