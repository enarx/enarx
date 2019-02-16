use super::super::super::{sev, Params};
use codicon::Decoder;

#[test]
fn test() {
    let bytes = include_bytes!("pek_oca_cek.cert");
    let mut rdr = &bytes[..];

    let pek = sev::Certificate::decode(&mut &mut rdr, Params).unwrap();
    assert_eq!(pek, sev::Certificate::Version1(sev::v1::Certificate {
        body: sev::v1::Body {
            version: sev::v1::Version(0, 17),
            pubkey: sev::v1::PublicKey {
                usage: sev::v1::Usage::PlatformEndorsementKey,
                algo: sev::v1::Algorithm::EcdsaSha256,
                key: bytes[0x010..][..1028].to_vec(),
            },
        },
        sig1: Some(sev::v1::Signature {
            usage: sev::v1::Usage::OwnerCertificateAuthority,
            algo: sev::v1::Algorithm::EcdsaSha256,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: Some(sev::v1::Signature {
            usage: sev::v1::Usage::ChipEndorsementKey,
            algo: sev::v1::Algorithm::EcdsaSha256,
            sig: bytes[0x624..][..512].to_vec(),
        }),
    }));
    
    let bytes = rdr;
    
    let oca = sev::Certificate::decode(&mut &mut rdr, Params).unwrap();
    assert_eq!(oca, sev::Certificate::Version1(sev::v1::Certificate {
        body: sev::v1::Body {
            version: sev::v1::Version(0, 17),
            pubkey: sev::v1::PublicKey {
                usage: sev::v1::Usage::OwnerCertificateAuthority,
                algo: sev::v1::Algorithm::EcdsaSha256,
                key: bytes[0x010..][..1028].to_vec(),
            },
        },
        sig1: Some(sev::v1::Signature {
            usage: sev::v1::Usage::OwnerCertificateAuthority,
            algo: sev::v1::Algorithm::EcdsaSha256,
            sig: bytes[0x41C..][..512].to_vec(),
        }),
        sig2: None,
    }));
    
    let bytes = rdr;
    
    let cek = sev::Certificate::decode(&mut &mut rdr, Params).unwrap();
    assert_eq!(cek, sev::Certificate::Version1(sev::v1::Certificate {
        body: sev::v1::Body {
            version: sev::v1::Version(0, 17),
            pubkey: sev::v1::PublicKey {
                usage: sev::v1::Usage::ChipEndorsementKey,
                algo: sev::v1::Algorithm::EcdsaSha256,
                key: bytes[0x010..][..1028].to_vec(),
            },
        },
        sig1: None,
        sig2: None,
    }));
}
