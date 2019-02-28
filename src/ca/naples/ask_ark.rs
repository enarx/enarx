use codicon::Decoder;

use super::super::super::Params;
use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("ask_ark.cert");
    let mut rdr = &bytes[..];

    let ask = Certificate::decode(&mut rdr, Params).unwrap();
    assert_eq!(ask, Certificate(Versioned::Version1(Body1 {
        key_id: 147429952972550494775834017433799571937,
        sig_id: 122178821951678173525318614033703090459,
        usage: Usage::AmdSevKey,
        pubexp: bytes[0x040..][..256].to_vec(),
        modulus: bytes[0x140..][..256].to_vec(),
        signature: bytes[0x240..][..256].to_vec(),
    })));

    let bytes = rdr;

    let ark = Certificate::decode(&mut rdr, Params).unwrap();
    assert_eq!(ark, Certificate(Versioned::Version1(Body1 {
        key_id: 122178821951678173525318614033703090459,
        sig_id: 122178821951678173525318614033703090459,
        usage: Usage::AmdRootKey,
        pubexp: bytes[0x040..][..256].to_vec(),
        modulus: bytes[0x140..][..256].to_vec(),
        signature: bytes[0x240..][..256].to_vec(),
    })));
}
