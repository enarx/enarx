use super::super::*;
use super::*;

#[test]
fn decode() {
    Usage::PlatformEndorsementKey.load(&mut &PEK[..]).unwrap();
}

#[test]
fn encode() {
    let pek = Usage::PlatformEndorsementKey.load(&mut &PEK[..]).unwrap();

    let mut output = Vec::new();
    pek.save(&mut output).unwrap();
    assert_eq!(PEK.len(), output.len());
    assert_eq!(PEK.to_vec(), output);
}

#[test]
fn verify() {
    let oca = Usage::OwnerCertificateAuthority.load(&mut &OCA[..]).unwrap();
    let cek = Usage::ChipEndorsementKey.load(&mut &CEK[..]).unwrap();
    let pek = Usage::PlatformEndorsementKey.load(&mut &PEK[..]).unwrap();

    oca.verify(&pek).unwrap();
    cek.verify(&pek).unwrap();

    assert!(pek.verify(&oca).is_err());
    assert!(pek.verify(&cek).is_err());
}
