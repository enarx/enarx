use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let oca = Certificate::decode(&mut OCA, Kind::Sev).unwrap();

    assert_eq!(oca, Certificate {
        version: 1,
        firmware: Some(Firmware(0, 16)),
        key: PublicKey {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                curve: Curve::P384,
                x: OCA[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: OCA[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::OwnerCertificateAuthority,
                algo: SigAlgo::EcdsaSha256,
                sig: OCA[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });
}

#[test]
fn encode() {
    let oca = Certificate::decode(&mut OCA, Kind::Sev).unwrap();

    let output = oca.encode_buf(()).unwrap();
    assert_eq!(OCA.len(), output.len());
    assert_eq!(OCA.to_vec(), output);

    let output = oca.body().unwrap();
    assert_eq!(SEV_SIG_OFFSET, output.len());
    assert_eq!(OCA[..SEV_SIG_OFFSET].to_vec(), output);
}

#[test]
fn verify() {
    let oca = Certificate::decode(&mut OCA, Kind::Sev).unwrap();
    (&oca, &oca).verify().unwrap();
}

#[test]
fn create() {
    let (oca, _) = Certificate::new(Usage::OwnerCertificateAuthority).unwrap();
    let buf = oca.encode_buf(()).unwrap();

    assert_eq!(oca, Certificate {
        version: 1,
        firmware: Some(Firmware(0, 0)),
        key: PublicKey {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                curve: Curve::P384,
                x: buf[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: buf[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::OwnerCertificateAuthority,
                algo: SigAlgo::EcdsaSha256,
                sig: buf[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });

    assert!((&oca, &oca).verify().is_ok());
}
