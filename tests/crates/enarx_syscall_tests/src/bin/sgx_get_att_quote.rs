// SPDX-License-Identifier: Apache-2.0

//! SGX attestation syscall test
//!
//! This test will be run only for SGX. It is designed to request a
//! Quote from get_attestation() and check that the first bytes of
//! the returned Quote in buf match expected values.

#![no_std]
#![no_main]
#![feature(asm_sym)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    if !is_enarx() {
        return Ok(());
    }

    let (size, tech) = get_att(None, None)?;

    /* this test is SGX-specific, so just return success if not running on SGX */
    if !matches!(tech, TeeTech::Sgx) {
        return Ok(());
    }

    let mut nonce = [0u8; 64];
    let mut buf = [0u8; 10000];
    let expected: [u8; 28] = [
        3, 0, 2, 0, 0, 0, 0, 0, 7, 0, 12, 0, 147, 154, 114, 51, 247, 156, 76, 169, 148, 10, 13,
        179, 149, 127, 6, 7,
    ];

    /* Ooops, the test fails because of false assumptions */
    if size > buf.len() {
        return Err(1);
    }

    let (size, tech) = get_att(Some(&mut nonce), Some(&mut buf))?;

    /* this test is SGX-specific, so just return success if not running on SGX */
    if !matches!(tech, TeeTech::Sgx) {
        return Ok(());
    }

    if size < expected.len() {
        return Err(1);
    }

    /* check beginning of quote matches expected value */
    if !buf.starts_with(&expected) {
        return Err(1);
    }

    Ok(())
}
