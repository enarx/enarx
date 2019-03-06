use codicon::{Decoder, Encoder};

use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("pdh.cert");

    let pdh = Certificate::decode(&mut &bytes[..], Kind::Sev).unwrap();
    assert_eq!(pdh, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 17 }),
        key: PublicKey {
            usage: Usage::PlatformDiffieHellman,
            algo: ExcAlgo::EcdhSha256.into(),
            key: Key::P384(EccKey {
                x: bytes[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: bytes[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::PlatformEndorsementKey,
                algo: SigAlgo::EcdsaSha256,
                sig: bytes[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });

    let mut output = Vec::new();
    pdh.encode(&mut output, ()).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
