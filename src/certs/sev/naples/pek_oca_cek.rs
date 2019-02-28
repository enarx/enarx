use codicon::Decoder;

use super::super::super::Params;
use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("pek_oca_cek.cert");
    let mut rdr = &bytes[..];

    let pek = Certificate::decode(&mut &mut rdr, Params).unwrap();
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

    let bytes = rdr;

    let oca = Certificate::decode(&mut &mut rdr, Params).unwrap();
    assert_eq!(oca, Certificate(Versioned::Version1(Body1 {
        version: Version1(0, 17),
        pubkey: PublicKey1 {
            usage: Usage::OwnerCertificateAuthority,
            algo: Algorithm::EcdsaSha256,
            key: bytes[0x010..][..1028].to_vec(),
        },
        sig1: Some(Signature1 {
            usage: Usage::OwnerCertificateAuthority,
            algo: Algorithm::EcdsaSha256,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: None,
    })));

    let bytes = rdr;

    let cek = Certificate::decode(&mut &mut rdr, Params).unwrap();
    assert_eq!(cek, Certificate(Versioned::Version1(Body1 {
        version: Version1(0, 17),
        pubkey: PublicKey1 {
            usage: Usage::ChipEndorsementKey,
            algo: Algorithm::EcdsaSha256,
            key: bytes[0x010..][..1028].to_vec(),
        },
        sig1: None,
        sig2: None,
    })));
}
