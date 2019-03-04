use codicon::{Decoder, Encoder};

use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("pek.cert");

    let pek = Certificate::decode(&mut &bytes[..], ()).unwrap();
    assert_eq!(pek, Certificate(Versioned::Version1(Body1 {
        version: Version1(0, 17),
        pubkey: PublicKey1 {
            usage: Usage::PlatformEndorsementKey,
            algo: Algorithm::EcdsaSha256,
            key: bytes[0x010..][..1028].to_vec(),
        },
        sig1: Some(Signature1 {
            usage: Usage::OwnerCertificateAuthority,
            algo: Algorithm::EcdsaSha256,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: Some(Signature1 {
            usage: Usage::ChipEndorsementKey,
            algo: Algorithm::EcdsaSha256,
            sig: bytes[0x624..][..512].to_vec(),
        }),
    })));

    let mut output = Vec::new();
    pek.encode(&mut output, ()).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
