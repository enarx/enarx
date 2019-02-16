use super::super::super::{sev, Params};
use codicon::{Decoder, Encoder};

#[test]
fn test() {
    let bytes = include_bytes!("cek.cert.fixed");

    let cek = sev::Certificate::decode(&mut &bytes[..], Params).unwrap();
    assert_eq!(cek, sev::Certificate::Version1(sev::v1::Certificate {
        body: sev::v1::Body {
            version: sev::v1::Version(0, 14),
            pubkey: sev::v1::PublicKey {
                usage: sev::v1::Usage::ChipEndorsementKey,
                algo: sev::v1::Algorithm::EcdsaSha256,
                key: bytes[0x010..][..1028].to_vec(),
            },
        },
        sig1: Some(sev::v1::Signature {
            usage: sev::v1::Usage::AmdSevKey,
            algo: sev::v1::Algorithm::RsaSha384,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: None,
    }));

    let mut output = Vec::new();
    cek.encode(&mut output, Params).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
