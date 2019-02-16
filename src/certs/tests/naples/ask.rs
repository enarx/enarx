use super::super::super::{ca, Params};
use codicon::{Decoder, Encoder};

#[test]
fn test() {
    let bytes = include_bytes!("ask.cert");

    let ask = ca::Certificate::decode(&mut &bytes[..], Params).unwrap();
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

    let mut output = Vec::new();
    ask.encode(&mut output, Params).unwrap();
    assert_eq!(bytes.len(), output.len());
    assert_eq!(bytes.to_vec(), output);
}
