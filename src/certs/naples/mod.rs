mod ark;
mod ask;
mod cek;
mod oca;
mod pek;
mod pdh;

const OCA: &[u8] = include_bytes!("oca.cert");
const ARK: &[u8] = include_bytes!("ark.cert");
const ASK: &[u8] = include_bytes!("ask.cert");
const CEK_SIG: &[u8] = include_bytes!("cek.sig.cert");
const CEK_UNS: &[u8] = include_bytes!("cek.uns.cert");
const PEK: &[u8] = include_bytes!("pek.cert");
const PDH: &[u8] = include_bytes!("pdh.cert");

const CA_SIG_OFFSET: usize = 0x40 + 2048 / 8 + 2048 / 8;
const SEV_SIG_OFFSET: usize = 0x414;

fn to4096(byte: &[u8]) -> [u8; 4096 / 8] {
    let mut buf = [0u8; 4096 / 8];

    for (i, b) in byte.iter().enumerate() {
        buf[i] = *b;
    }

    buf
}

fn to576(byte: &[u8]) -> [u8; 576 / 8] {
    let mut buf = [0u8; 576 / 8];

    for (i, b) in byte.iter().enumerate() {
        buf[i] = *b;
    }

    buf
}

#[test]
fn chain() {
    use crate::certs::{Certificate, Kind, Full, Usage};
    use codicon::{Decoder, Encoder};
    use std::collections::HashMap;

    const ALL: &[(Kind, &[u8])] = &[
        (Kind::Sev, PDH), (Kind::Sev, PEK), (Kind::Sev, OCA),
        (Kind::Sev, CEK_SIG), (Kind::Ca, ASK), (Kind::Ca, ARK)
    ];

    // Fill up a HashMap with all our certs.
    let mut old = HashMap::new();
    for (k, c) in ALL.iter().cloned() {
        let crt = Certificate::decode(&mut &c[..], k).unwrap();
        old.insert(crt.key.usage, crt);
    }

    // Encode the chain.
    let mut buf = Vec::new();
    old.encode(&mut buf, Full).unwrap();

    // Confirm the order of the elements in the chain.
    let mut rdr = &buf[..];
    for u in Usage::ALL.iter() {
        let cert = Certificate::decode(&mut rdr, u.kind()).unwrap();
        assert_eq!(cert.key.usage, *u);
    }

    assert_eq!(old, HashMap::decode(&mut &buf[..], Full).unwrap());
}
