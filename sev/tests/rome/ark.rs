// SPDX-License-Identifier: Apache-2.0

use super::*;
use ::sev::certs::builtin::rome::*;

#[test]
fn decode() {
    ca::Certificate::decode(&mut &ARK[..], ()).unwrap();
}

#[test]
fn encode() {
    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();

    let mut output = Vec::new();
    ark.encode(&mut output, ()).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);

    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();

    let mut output = Vec::new();
    ark.encode(&mut output, ()).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);
}

#[cfg(feature = "openssl")]
// FIXME: https://github.com/enarx/enarx/issues/581
#[ignore]
#[test]
fn verify() {
    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();
    (&ark, &ark).verify().unwrap();
}
