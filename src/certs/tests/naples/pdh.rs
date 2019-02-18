use super::super::super::{sev, Params};
use codicon::{Decoder, Encoder};

#[test]
fn test() {
    let bytes = include_bytes!("pdh.cert");

    let pdh = sev::Certificate::decode(&mut &bytes[..], Params).unwrap();
    let val = sev::Certificate::Version1(sev::v1::Certificate {
        version: sev::v1::Version(0, 17),
        pubkey: sev::v1::PublicKey {
            usage: sev::v1::Usage::PlatformDiffieHellman,
            algo: sev::v1::Algorithm::EcdhSha256,
            key: bytes[0x010..][..1028].to_vec(),
        },
        sig1: Some(sev::v1::Signature {
            usage: sev::v1::Usage::PlatformEndorsementKey,
            algo: sev::v1::Algorithm::EcdsaSha256,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: None,
    });

    assert_eq!(pdh, val);

    let mut output = Vec::new();
    pdh.encode(&mut output, Params).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
