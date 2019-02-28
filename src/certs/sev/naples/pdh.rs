use codicon::{Decoder, Encoder};

use super::super::super::Params;
use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("pdh.cert");

    let pdh = Certificate::decode(&mut &bytes[..], Params).unwrap();
    assert_eq!(pdh, Certificate(Versioned::Version1(Body1 {
        version: Version1(0, 17),
        pubkey: PublicKey1 {
            usage: Usage::PlatformDiffieHellman,
            algo: Algorithm::EcdhSha256,
            key: bytes[0x010..][..1028].to_vec(),
        },
        sig1: Some(Signature1 {
            usage: Usage::PlatformEndorsementKey,
            algo: Algorithm::EcdsaSha256,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: None,
    })));

    let mut output = Vec::new();
    pdh.encode(&mut output, Params).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
