use codicon::Decoder;

use super::super::*;
use super::*;

#[test]
fn decode() {
    let cek = Certificate::decode(&mut &CEK_UNS[..], Kind::Sev).unwrap();
    assert_eq!(cek, Certificate {
        version: 1,
        sigs: [None, None],
        firmware: Some(Firmware(0, 16)),
        key: PublicKey {
            usage: Usage::ChipEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: KeyType::Ecc(EccKey {
                c: Curve::P384,
                x: to576(&CEK_UNS[0x010..0x414][0x04..][..384 / 8]),
                y: to576(&CEK_UNS[0x010..0x414][0x4C..][..384 / 8]),
            }),
            id: None,
        },
    });
    assert_eq!(cek.sigs, [None, None]);

    let cek = Certificate::decode(&mut &CEK_SIG[..], Kind::Sev).unwrap();
    assert_eq!(cek, Certificate {
        version: 1,
        sigs: [None, None],
        firmware: Some(Firmware(0, 14)),
        key: PublicKey {
            usage: Usage::ChipEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: KeyType::Ecc(EccKey {
                c: Curve::P384,
                x: to576(&CEK_SIG[0x010..0x414][0x04..][..384 / 8]),
                y: to576(&CEK_SIG[0x010..0x414][0x4C..][..384 / 8]),
            }),
            id: None,
        },
    });
    assert_eq!(cek.sigs, [
        Some(Signature {
            usage: Usage::AmdSevKey,
            algo: SigAlgo::RsaSha256,
            sig: to4096(&CEK_SIG[0x41C..0x61C]),
            id: None,
        }),
        None
    ]);
}

#[test]
fn encode() {
    let cek = Certificate::decode(&mut &CEK_SIG[..], Kind::Sev).unwrap();

    let output = cek.encode_buf(Full).unwrap();
    assert_eq!(CEK_SIG.len(), output.len());
    assert_eq!(CEK_SIG.to_vec(), output);

    let output = cek.encode_buf(Body).unwrap();
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
