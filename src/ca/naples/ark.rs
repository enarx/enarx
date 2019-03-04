use codicon::{Decoder, Encoder};

use super::super::*;

#[test]
fn v1() {
    let bytes = include_bytes!("ark.cert");

    let ark = Certificate::decode(&mut &bytes[..], ()).unwrap();
    assert_eq!(ark, Certificate(Versioned::Version1(Body1 {
        key_id: 122178821951678173525318614033703090459,
        sig_id: 122178821951678173525318614033703090459,
        usage: Usage::AmdRootKey,
        pubexp: bytes[0x040..][..256].to_vec(),
        modulus: bytes[0x140..][..256].to_vec(),
        signature: bytes[0x240..][..256].to_vec(),
    })));

    let mut output = Vec::new();
    ark.encode(&mut output, ()).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
