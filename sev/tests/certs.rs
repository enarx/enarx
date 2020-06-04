// SPDX-License-Identifier: Apache-2.0

mod naples;
mod rome;

use ::sev::certs::*;
use codicon::Decoder;

#[test]
fn test_for_verify_false_positive() {
    // https://github.com/enarx/enarx/issues/520
    let naples_cek = sev::Certificate::decode(&mut &naples::CEK[..], ()).unwrap();
    let rome_ask = ca::Certificate::decode(&mut &builtin::rome::ASK[..], ()).unwrap();
    assert!((&rome_ask, &naples_cek).verify().is_err());
}
