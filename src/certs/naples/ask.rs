use super::super::*;
use super::*;

#[test]
fn decode() {
    Usage::AmdSevKey.load(&mut &ASK[..]).unwrap();
}

#[test]
fn encode() {
    let ask = Usage::AmdSevKey.load(&mut &ASK[..]).unwrap();

    let mut output = Vec::new();
    ask.save(&mut output).unwrap();
    assert_eq!(ASK.len(), output.len());
    assert_eq!(ASK.to_vec(), output);
}

#[test]
fn verify() {
    let one = Usage::AmdRootKey.load(&mut ARK).unwrap();
    let two = Usage::AmdSevKey.load(&mut ASK).unwrap();

    one.verify(&two).unwrap();
    assert!(two.verify(&one).is_err());
}
