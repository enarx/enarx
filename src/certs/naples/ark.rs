#![allow(clippy::unreadable_literal)]

use std::num::NonZeroU128;
use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let ark = Certificate::decode(&mut &ARK[..], Kind::Ca).unwrap();
    assert_eq!(ark, Certificate {
        version: 1,
        firmware: None,
        sigs: [None, None],
        key: PublicKey {
            usage: Usage::AmdRootKey,
            algo: SigAlgo::RsaSha256.into(),
            key: KeyType::Rsa(RsaKey {
                pubexp: to4096(&ARK[0x040..][..256]),
                modulus: to4096(&ARK[0x140..][..256]),
            }),
            id: NonZeroU128::new(122178821951678173525318614033703090459),
        },
    });
    assert_eq!(ark.sigs, [
        Some(Signature {
            usage: Usage::AmdRootKey,
            algo: SigAlgo::RsaSha256,
            sig: to4096(&ARK[0x240..][..256]),
            id: NonZeroU128::new(122178821951678173525318614033703090459),
        }),
        None
    ]);
}

#[test]
fn encode() {
    let ark = Certificate::decode(&mut &ARK[..], Kind::Ca).unwrap();

    let output = ark.encode_buf(Full).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);

    let output = ark.encode_buf(Body).unwrap();
    assert_eq!(CA_SIG_OFFSET, output.len());
    assert_eq!(ARK[..CA_SIG_OFFSET].to_vec(), output);
}

#[test]
fn verify() {
    let ark = Certificate::decode(&mut ARK, Kind::Ca).unwrap();
    (&ark, &ark).verify().unwrap();
}

#[test]
fn create() {
    // Generate the key pair
    let (key, prv) = Usage::AmdRootKey.generate().unwrap();
    assert!(key.id.is_some());
    assert_eq!(key.usage, Usage::AmdRootKey);
    assert_eq!(key.algo, Algo::Sig(SigAlgo::RsaSha256));

    // Construct an ARK
    let mut ark = Certificate {
        sigs: [None, None],
        firmware: None,
        version: 1,
        key: key,
    };

    // Self-sign the ARK
    let buf = ark.encode_buf(Body).unwrap();
    ark.sigs[0] = Some(ark.key.sign(&buf, &prv).unwrap());

    // Verify the self-signature
    [&ark].verify().unwrap();
}
