use codicon::{Decoder, Encoder};

use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("cek.cert.fixed");

    let cek = Certificate::decode(&mut &bytes[..], Kind::Sev).unwrap();
    assert_eq!(cek, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 14 }),
        key: PublicKey {
            usage: Usage::ChipEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::P384(EccKey {
                x: bytes[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: bytes[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::AmdSevKey,
                algo: SigAlgo::RsaSha384,
                sig: bytes[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });

    let mut output = Vec::new();
    cek.encode(&mut output, ()).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
