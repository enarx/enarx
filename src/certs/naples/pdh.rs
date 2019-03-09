use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let pdh = Certificate::decode(&mut &PDH[..], Kind::Sev).unwrap();

    assert_eq!(pdh, Certificate {
        version: 1,
        firmware: Some(Firmware { major: 0, minor: 16 }),
        key: PublicKey {
            usage: Usage::PlatformDiffieHellman,
            algo: ExcAlgo::EcdhSha256.into(),
            key: Key::Ecc(EccKey {
                curve: Curve::P384,
                x: PDH[0x010..0x414][0x04..][..384 / 8].to_vec(),
                y: PDH[0x010..0x414][0x4C..][..384 / 8].to_vec(),
            }),
            id: None,
        },
        sigs: vec! {
            Signature {
                usage: Usage::PlatformEndorsementKey,
                algo: SigAlgo::EcdsaSha256,
                sig: PDH[0x41C..0x61C].to_vec(),
                id: None,
            }
        }
    });
}

#[test]
fn encode() {
    let pdh = Certificate::decode(&mut &PDH[..], Kind::Sev).unwrap();

    let output = pdh.encode_buf(()).unwrap();
    assert_eq!(PDH.len(), output.len());
    assert_eq!(PDH.to_vec(), output);

    let output = pdh.encode_buf(Ring).unwrap();
    assert_eq!(SEV_SIG_OFFSET, output.len());
    assert_eq!(PDH[..SEV_SIG_OFFSET].to_vec(), output);
}

#[test]
fn verify() {
    let one = Certificate::decode(&mut PEK, Kind::Sev).unwrap();
    let two = Certificate::decode(&mut PDH, Kind::Sev).unwrap();

    (&one, &two).verify().unwrap();
    assert!((&two, &one).verify().is_err());
}
