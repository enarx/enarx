// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use openssl::hash::{DigestBytes, MessageDigest};

#[derive(Copy, Clone, Debug)]
pub enum Kind {
    Sha256,
    Null,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Sha256 => "sha256",
            Self::Null => "null",
        };

        write!(f, "{}", s)
    }
}

impl From<Kind> for MessageDigest {
    fn from(k: Kind) -> MessageDigest {
        match k {
            Kind::Sha256 => MessageDigest::sha256(),
            Kind::Null => MessageDigest::null(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Measurement {
    pub kind: Kind,
    pub digest: DigestBytes,
}
