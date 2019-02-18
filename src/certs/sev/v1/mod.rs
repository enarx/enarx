mod decoders;
mod encoders;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Usage {
    OwnerCertificateAuthority,
    PlatformEndorsementKey,
    PlatformDiffieHellman,
    ChipEndorsementKey,
    AmdRootKey,
    AmdSevKey,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha256,
    EcdsaSha256,
    EcdhSha256,
    RsaSha384,
    EcdsaSha384,
    EcdhSha384,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u8, pub u8);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub usage: Usage,
    pub algo: Algorithm,
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub usage: Usage,
    pub algo: Algorithm,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub version: Version,
    pub pubkey: PublicKey,
    pub sig1: Option<Signature>,
    pub sig2: Option<Signature>,
}
