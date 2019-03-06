use codicon::Decoder;

use super::super::*;
use super::*;

#[test]
fn decode() {
    let cek = Certificate::decode(&mut &CEK_UNS[..], Kind::Sev).unwrap();
    assert_eq!(cek, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 16 }),
        key: PublicKey {
            usage: Usage::ChipEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                curve: Curve::P384,
                x: CEK_UNS[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: CEK_UNS[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {}
    });

    let cek = Certificate::decode(&mut &CEK_SIG[..], Kind::Sev).unwrap();
    assert_eq!(cek, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 14 }),
        key: PublicKey {
            usage: Usage::ChipEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                curve: Curve::P384,
                x: CEK_SIG[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: CEK_SIG[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::AmdSevKey,
                algo: SigAlgo::RsaSha256,
                sig: CEK_SIG[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });
}

#[test]
fn encode() {
    let cek = Certificate::decode(&mut &CEK_SIG[..], Kind::Sev).unwrap();

    let output = cek.encode_buf(()).unwrap();
    assert_eq!(CEK_SIG.len(), output.len());
    assert_eq!(CEK_SIG.to_vec(), output);

    let output = cek.encode_buf(Ring).unwrap();
    assert_eq!(SEV_SIG_OFFSET, output.len());
    assert_eq!(CEK_SIG[..SEV_SIG_OFFSET].to_vec(), output);
}

#[test]
fn verify() {
    let one = Certificate::decode(&mut ASK, Kind::Ca).unwrap();
    let two = Certificate::decode(&mut CEK_SIG, Kind::Sev).unwrap();

    (&one, &two).verify().unwrap();
    assert!((&two, &one).verify().is_err());
}
