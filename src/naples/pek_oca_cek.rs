use codicon::Decoder;

use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("pek_oca_cek.cert");
    let mut rdr = &bytes[..];

    let pek = Certificate::decode(&mut &mut rdr, Kind::Sev).unwrap();
    assert_eq!(pek, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 17 }),
        key: PublicKey {
            usage: Usage::PlatformEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::P384(EccKey {
                x: bytes[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: bytes[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::OwnerCertificateAuthority,
                algo: SigAlgo::EcdsaSha256,
                sig: bytes[0x41C..0x61C].to_vec(),
                id: None,
            },
            Signature {
                usage: Usage::ChipEndorsementKey,
                algo: SigAlgo::EcdsaSha256,
                sig: bytes[0x624..0x824].to_vec(),
                id: None,
            }
        }
    });

    let bytes = rdr;

    let oca = Certificate::decode(&mut &mut rdr, Kind::Sev).unwrap();
    assert_eq!(oca, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 17 }),
        key: PublicKey {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::P384(EccKey {
                x: bytes[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: bytes[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::OwnerCertificateAuthority,
                algo: SigAlgo::EcdsaSha256,
                sig: bytes[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });

    let bytes = rdr;

    let cek = Certificate::decode(&mut &mut rdr, Kind::Sev).unwrap();
    assert_eq!(cek, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 17 }),
        key: PublicKey {
            usage: Usage::ChipEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::P384(EccKey {
                x: bytes[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: bytes[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {}
    });
}
