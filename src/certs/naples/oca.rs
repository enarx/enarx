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
            key: KeyType::Ecc(EccKey {
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

    let output = oca.encode_buf(Full).unwrap();
    assert_eq!(OCA.len(), output.len());
    assert_eq!(OCA.to_vec(), output);

    let output = oca.encode_buf(Body).unwrap();
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
    // Generate the key pair
    let (key, prv) = Usage::OwnerCertificateAuthority.generate().unwrap();
    assert!(key.id.is_none());
    assert_eq!(key.usage, Usage::OwnerCertificateAuthority);
    assert_eq!(key.algo, Algo::Sig(SigAlgo::EcdsaSha256));

    // Construct an OCA
    let mut oca = Certificate {
        firmware: Some(Firmware(0, 0)),
        sigs: [None, None],
        version: 1,
        key: key,
    };

    // Self-sign the OCA
    let buf = oca.encode_buf(Body).unwrap();
    oca.sigs[0] = Some(oca.key.sign(&buf, &prv).unwrap());

    // Verify the self-signature
    [&oca].verify().unwrap();
}
