// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod common;
use common::IntegrationTest;

#[test]
#[cfg_attr(not(any(has_sgx, has_sev, has_kvm)), ignore)]
fn clock_gettime() {
    IntegrationTest::new("clock_gettime").run(5, 0, "", "", "");
}
