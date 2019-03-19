use super::super::*;
use super::*;

#[test]
fn decode() {
    Usage::PlatformDiffieHellman.load(&mut &PDH[..]).unwrap();
}

#[test]
fn encode() {
    let pdh = Usage::PlatformDiffieHellman.load(&mut &PDH[..]).unwrap();

    let mut output = Vec::new();
    pdh.save(&mut output).unwrap();
    assert_eq!(PDH.len(), output.len());
    assert_eq!(PDH.to_vec(), output);
}

#[test]
fn verify() {
    let one = Usage::PlatformEndorsementKey.load(&mut PEK).unwrap();
    let two = Usage::PlatformDiffieHellman.load(&mut PDH).unwrap();

    one.verify(&two).unwrap();
    assert!(two.verify(&one).is_err());
}
