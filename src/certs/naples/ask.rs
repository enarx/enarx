#![allow(clippy::unreadable_literal)]

use std::num::NonZeroU128;
use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let ask = Certificate::decode(&mut &ASK[..], Kind::Ca).unwrap();
    assert_eq!(ask, Certificate {
        version: 1,
        firmware: None,
        sigs: [None, None],
        key: PublicKey {
            usage: Usage::AmdSevKey,
            algo: SigAlgo::RsaSha256.into(),
            key: Key::Rsa(RsaKey {
                pubexp: to4096(&ASK[0x040..][..256]),
                modulus: to4096(&ASK[0x140..][..256]),
            }),
            id: NonZeroU128::new(147429952972550494775834017433799571937),
        },
    });

    assert_eq!(ask.sigs, [
        Some(Signature {
            usage: Usage::AmdRootKey,
            algo: SigAlgo::RsaSha256,
            sig: to4096(&ASK[0x240..][..256]),
            id: NonZeroU128::new(122178821951678173525318614033703090459),
        }),
        None
    ]);
}

#[test]
fn encode() {
    let ask = Certificate::decode(&mut &ASK[..], Kind::Ca).unwrap();

    let output = ask.encode_buf(()).unwrap();
    assert_eq!(ASK.len(), output.len());
    assert_eq!(ASK.to_vec(), output);

    let output = ask.body().unwrap();
    assert_eq!(CA_SIG_OFFSET, output.len());
    assert_eq!(ASK[..CA_SIG_OFFSET].to_vec(), output);
}

#[test]
fn verify() {
    let one = Certificate::decode(&mut ARK, Kind::Ca).unwrap();
    let two = Certificate::decode(&mut ASK, Kind::Ca).unwrap();

    (&one, &two).verify().unwrap();
    assert!((&two, &one).verify().is_err());
}
