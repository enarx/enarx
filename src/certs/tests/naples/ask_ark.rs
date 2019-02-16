use super::super::super::{ca, Params};
use codicon::Decoder;

#[test]
fn test() {
    let bytes = include_bytes!("ask_ark.cert.fixed");
    let mut rdr = &bytes[..];

    let ask = ca::Certificate::decode(&mut rdr, Params).unwrap();
    assert_eq!(ask, ca::Certificate::Version1(ca::v1::Certificate {
        body: ca::v1::Body {
            key_id: 147429952972550494775834017433799571937,
            sig_id: 122178821951678173525318614033703090459,
            usage: ca::v1::Usage::AmdSevKey,
            pubexp: bytes[0x040..][..256].to_vec(),
            modulus: bytes[0x140..][..256].to_vec(),
        },
        signature: bytes[0x240..][..256].to_vec(),
    }));
    
    let bytes = rdr;

    let ark = ca::Certificate::decode(&mut rdr, Params).unwrap();
    assert_eq!(ark, ca::Certificate::Version1(ca::v1::Certificate {
        body: ca::v1::Body {
            key_id: 122178821951678173525318614033703090459,
            sig_id: 122178821951678173525318614033703090459,
            usage: ca::v1::Usage::AmdRootKey,
            pubexp: bytes[0x040..][..256].to_vec(),
            modulus: bytes[0x140..][..256].to_vec(),
        },
        signature: bytes[0x240..][..256].to_vec(),
    }));
}
