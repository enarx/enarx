// SPDX-License-Identifier: Apache-2.0

use super::*;
use ::sev::certs::builtin::rome::*;

#[test]
fn decode() {
    ca::Certificate::decode(&mut &ASK[..], ()).unwrap();
}

#[test]
fn encode() {
    let ask = ca::Certificate::decode(&mut &ASK[..], ()).unwrap();

    let mut output = Vec::new();
    ask.encode(&mut output, ()).unwrap();
    assert_eq!(ASK.len(), output.len());
    assert_eq!(ASK.to_vec(), output);
}

#[cfg(feature = "openssl")]
// FIXME: https://github.com/enarx/enarx/issues/581
#[ignore]
#[test]
fn verify() {
    let ark = ca::Certificate::decode(&mut ARK, ()).unwrap();
    let ask = ca::Certificate::decode(&mut ASK, ()).unwrap();

    (&ark, &ask).verify().unwrap();
    assert!((&ask, &ark).verify().is_err());
}
