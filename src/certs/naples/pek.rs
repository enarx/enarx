use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let pek = Certificate::decode(&mut &PEK[..], Kind::Sev).unwrap();

    assert_eq!(pek, Certificate {
        version: 1,
        firmware: Some(Firmware(0, 16)),
        key: PublicKey {
            usage: Usage::PlatformEndorsementKey,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                curve: Curve::P384,
                x: PEK[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: PEK[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::OwnerCertificateAuthority,
                algo: SigAlgo::EcdsaSha256,
                sig: PEK[0x41C..0x61C].to_vec(),
                id: None,
            },
            Signature {
                usage: Usage::ChipEndorsementKey,
                algo: SigAlgo::EcdsaSha256,
                sig: PEK[0x624..0x824].to_vec(),
                id: None,
            }
        }
    });
}

#[test]
fn encode() {
    let pek = Certificate::decode(&mut &PEK[..], Kind::Sev).unwrap();

    let output = pek.encode_buf(()).unwrap();
    assert_eq!(PEK.len(), output.len());
    assert_eq!(PEK.to_vec(), output);

    let output = pek.body().unwrap();
    assert_eq!(SEV_SIG_OFFSET, output.len());
    assert_eq!(PEK[..SEV_SIG_OFFSET].to_vec(), output);
}

#[test]
fn verify() {
    let oca = Certificate::decode(&mut OCA, Kind::Sev).unwrap();
    let cek = Certificate::decode(&mut CEK_SIG, Kind::Sev).unwrap();
    let pek = Certificate::decode(&mut PEK, Kind::Sev).unwrap();

    (&oca, &pek).verify().unwrap();
    (&cek, &pek).verify().unwrap();

    assert!((&pek, &oca).verify().is_err());
    assert!((&pek, &cek).verify().is_err());
}
