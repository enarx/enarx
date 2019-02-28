mod decoders;
mod encoders;

#[cfg(test)]
mod naples;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Usage {
    OwnerCertificateAuthority,
    PlatformEndorsementKey,
    PlatformDiffieHellman,
    ChipEndorsementKey,
    AmdRootKey,
    AmdSevKey,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    RsaSha256,
    EcdsaSha256,
    EcdhSha256,
    RsaSha384,
    EcdsaSha384,
    EcdhSha384,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Version1(pub(crate) u8, pub(crate) u8);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicKey1 {
    pub(crate) usage: Usage,
    pub(crate) algo: Algorithm,
    pub(crate) key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signature1 {
    pub(crate) usage: Usage,
    pub(crate) algo: Algorithm,
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Body1 {
    pub(crate) version: Version1,
    pub(crate) pubkey: PublicKey1,
    pub(crate) sig1: Option<Signature1>,
    pub(crate) sig2: Option<Signature1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Versioned {
    Version1(Body1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate(pub(crate) Versioned);
