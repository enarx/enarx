use super::super::*;
use super::*;

#[test]
fn decode() {
    Usage::ChipEndorsementKey.load(&mut &CEK[..]).unwrap();
}

#[test]
fn encode() {
    let cek = Usage::ChipEndorsementKey.load(&mut &CEK[..]).unwrap();

    let mut output = Vec::new();
    cek.save(&mut output).unwrap();
    assert_eq!(CEK.len(), output.len());
    assert_eq!(CEK.to_vec(), output);
}

#[test]
fn verify() {
    let one = Usage::AmdSevKey.load(&mut ASK).unwrap();
    let two = Usage::ChipEndorsementKey.load(&mut CEK).unwrap();

    one.verify(&two).unwrap();
    assert!(two.verify(&one).is_err());
}
