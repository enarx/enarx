use super::super::*;
use super::*;

#[test]
fn decode() {
    Usage::OwnerCertificateAuthority.load(&mut &OCA[..]).unwrap();
}

#[test]
fn encode() {
    let oca = Usage::OwnerCertificateAuthority.load(&mut &OCA[..]).unwrap();

    let mut output = Vec::new();
    oca.save(&mut output).unwrap();
    assert_eq!(OCA.len(), output.len());
    assert_eq!(OCA.to_vec(), output);
}

#[test]
fn verify() {
    let oca = Usage::OwnerCertificateAuthority.load(&mut &OCA[..]).unwrap();
    oca.verify(&oca).unwrap();
}

#[test]
fn create() {
    let mut pdh = Usage::PlatformDiffieHellman.load(&mut &PDH[..]).unwrap();
    let (crt, key) = Certificate::oca().unwrap();

    assert!(pdh.verify(&pdh).is_err());
    assert!(crt.verify(&pdh).is_err());
    crt.verify(&crt).unwrap();

    key.sign(&mut pdh).unwrap();
    crt.verify(&pdh).unwrap();
}
