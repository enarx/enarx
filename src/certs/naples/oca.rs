use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let oca = Certificate::decode(&mut OCA, Kind::Sev).unwrap();

    assert_eq!(oca, Certificate {
        version: 1,
        sigs: [None, None],
        firmware: Some(Firmware(0, 16)),
        key: PublicKey {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                c: Curve::P384,
                x: to576(&OCA[0x010..0x414][0x04..][..384 / 8]),
                y: to576(&OCA[0x010..0x414][0x4C..][..384 / 8]),
            }),
            id: None,
        },
    });
    assert_eq!(oca.sigs, [
        Some(Signature {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256,
            sig: to4096(&OCA[0x41C..0x61C]),
            id: None,
        }),
        None
    ]);
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
        sigs: [None, None],
        firmware: Some(Firmware(0, 0)),
        key: PublicKey {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256.into(),
            key: Key::Ecc(EccKey {
                c: Curve::P384,
                x: to576(&buf[0x010..0x414][0x04..][..384 / 8]),
                y: to576(&buf[0x010..0x414][0x4C..][..384 / 8]),
            }),
            id: None,
        },
    });
    assert_eq!(oca.sigs, [
        Some(Signature {
            usage: Usage::OwnerCertificateAuthority,
            algo: SigAlgo::EcdsaSha256,
            sig: to4096(&buf[0x41C..0x61C]),
            id: None,
        }),
        None
    ]);

    assert!((&oca, &oca).verify().is_ok());
}
