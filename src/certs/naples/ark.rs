use super::super::*;
use super::*;

#[test]
fn decode() {
    Usage::AmdRootKey.load(&mut &ARK_BAD[..]).unwrap();
    Usage::AmdRootKey.load(&mut &ARK[..]).unwrap();
}

#[test]
fn encode() {
    let ark = Usage::AmdRootKey.load(&mut &ARK_BAD[..]).unwrap();

    let mut output = Vec::new();
    ark.save(&mut output).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);

    let ark = Usage::AmdRootKey.load(&mut &ARK[..]).unwrap();

    let mut output = Vec::new();
    ark.save(&mut output).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);
}

#[test]
fn verify() {
    let ark = Usage::AmdRootKey.load(&mut &ARK_BAD[..]).unwrap();
    ark.verify(&ark).unwrap();

    let ark = Usage::AmdRootKey.load(&mut &ARK[..]).unwrap();
    ark.verify(&ark).unwrap();
}
