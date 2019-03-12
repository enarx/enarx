use codicon::Decoder;
use super::super::*;
use super::*;

#[test]
fn decode() {
    let pdh = Certificate::decode(&mut &PDH[..], Kind::Sev).unwrap();

    assert_eq!(pdh, Certificate {
        version: 1,
        sigs: [None, None],
        firmware: Some(Firmware(0, 16)),
        key: PublicKey {
            usage: Usage::PlatformDiffieHellman,
            algo: ExcAlgo::EcdhSha256.into(),
            key: Key::Ecc(EccKey {
                c: Curve::P384,
                x: to576(&PDH[0x010..0x414][0x04..][..384 / 8]),
                y: to576(&PDH[0x010..0x414][0x4C..][..384 / 8]),
            }),
            id: None,
        },
    });
    assert_eq!(pdh.sigs, [
        Some(Signature {
            usage: Usage::PlatformEndorsementKey,
            algo: SigAlgo::EcdsaSha256,
            sig: to4096(&PDH[0x41C..0x61C]),
            id: None,
        }),
        None
    ]);
}

#[test]
fn encode() {
    let pdh = Certificate::decode(&mut &PDH[..], Kind::Sev).unwrap();

    let output = pdh.encode_buf(()).unwrap();
    assert_eq!(PDH.len(), output.len());
    assert_eq!(PDH.to_vec(), output);

    let output = pdh.body().unwrap();
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
