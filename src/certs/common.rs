use super::*;

#[derive(Copy, Clone, Debug)]
pub struct Internal<T>(pub T);

pub struct IdHash(pub openssl::pkey::Id, pub openssl::hash::MessageDigest);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Signing,
    Exchange
}

impl From<Usage> for Kind {
    #[inline]
    fn from(value: Usage) -> Kind {
        match value {
            Usage::PlatformDiffieHellman => Kind::Exchange,
            _ => Kind::Signing,
        }
    }
}
