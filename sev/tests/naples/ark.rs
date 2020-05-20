// SPDX-License-Identifier: Apache-2.0

use super::*;
use ::sev::certs::builtin::naples::*;

#[test]
fn decode() {
    let bad = ca::Certificate::decode(&mut &ARK_BAD[..], ()).unwrap();
    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();
    assert_eq!(ark, bad);
}

#[test]
fn encode() {
    let ark = ca::Certificate::decode(&mut &ARK_BAD[..], ()).unwrap();

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
#[test]
fn verify() {
    let ark = ca::Certificate::decode(&mut &ARK_BAD[..], ()).unwrap();
    (&ark, &ark).verify().unwrap();

    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();
    (&ark, &ark).verify().unwrap();
}
