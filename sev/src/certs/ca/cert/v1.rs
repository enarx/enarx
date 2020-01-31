// Copyright 2019 Red Hat
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

const NAPLES_ARK_SIG: &[u8] = include_bytes!("../../../../tests/naples/ark.cert.sig");
const NAPLES_ARK: Preamble = Preamble {
    ver: 1u32.to_le(),
    data: Data {
        kid: 122178821951678173525318614033703090459u128.to_le(),
        sid: 122178821951678173525318614033703090459u128.to_le(),
        usage: Usage::ARK,
        reserved: 0,
        psize: 2048u32.to_le(),
        msize: 2048u32.to_le(),
    },
};

enum Size {
    Small,
    Large,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Data {
    pub kid: u128,
    pub sid: u128,
    pub usage: Usage,
    pub reserved: u128,
    pub psize: u32,
    pub msize: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Preamble {
    pub ver: u32,
    pub data: Data,
}

impl Preamble {
    fn size(&self) -> Result<Size> {
        if self.data.psize != self.data.msize {
            return Err(ErrorKind::InvalidInput.into());
        }

        match u32::from_le(self.data.msize) {
            2048 => Ok(Size::Small),
            4096 => Ok(Size::Large),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Body<T: Copy + Clone> {
    preamble: Preamble,
    pubexp: T,
    modulus: T,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Contents<T: Copy + Clone> {
    body: Body<T>,
    signature: T,
}

macro_rules! traits {
    ($($size:expr)+) => {
        $(
            impl std::fmt::Debug for Body<[u8; $size]> {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "Body<[u8; {}]> {{", $size)?;
                    write!(f, " preamble: {:?},", self.preamble)?;
                    write!(f, " pubexp: {:?},", &self.pubexp[..])?;
                    write!(f, " modulus: {:?} ", &self.modulus[..])?;
                    write!(f, "}}")
                }
            }

            impl Eq for Body<[u8; $size]> {}
            impl PartialEq for Body<[u8; $size]> {
                fn eq(&self, other: &Body<[u8; $size]>) -> bool {
                    self.preamble == other.preamble
                        && self.pubexp[..] == other.pubexp[..]
                        && self.modulus[..] == other.modulus[..]
                }
            }

            impl std::fmt::Debug for Contents<[u8; $size]> {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "Contents<[u8; {}]> {{", $size)?;
                    write!(f, " body: {:?},", self.body)?;
                    write!(f, " signature: {:?} ", &self.signature[..])?;
                    write!(f, "}}")
                }
            }

            impl Eq for Contents<[u8; $size]> {}
            impl PartialEq for Contents<[u8; $size]> {
                fn eq(&self, other: &Contents<[u8; $size]>) -> bool {
                    self.body == other.body
                        && self.signature[..] == other.signature[..]
                }
            }

            impl codicon::Decoder<Preamble> for Contents<[u8; $size]> {
                type Error = Error;

                fn decode(reader: &mut impl Read, preamble: Preamble) -> Result<Self> {
                    let mut pubexp = [0u8; $size];
                    let mut modulus = [0u8; $size];
                    let mut signature = [0u8; $size];

                    reader.read_exact(&mut pubexp[..])?;
                    reader.read_exact(&mut modulus[..])?;

                    // The Naples ARK is malformed. See this bug for details:
                    //    https://github.com/AMDESE/AMDSEV/issues/17
                    //
                    // We work around this by catching EOF and injecting a
                    // valid signature that we received from AMD. We only do
                    // this for the Naples ARK.
                    if let Err(e) = reader.read_exact(&mut signature[..]) {
                        if e.kind() != ErrorKind::UnexpectedEof
                            && preamble != NAPLES_ARK {
                            return Err(e);
                        }

                        signature[..].copy_from_slice(NAPLES_ARK_SIG);
                    }

                    Ok(Self { body: Body { preamble, pubexp, modulus }, signature })
                }
            }
        )+
    };
}

traits!(256 512);

#[repr(C)]
#[derive(Copy, Clone)]
pub union Certificate {
    pub preamble: Preamble,
    small: Contents<[u8; 256]>,
    large: Contents<[u8; 512]>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if unsafe { self.preamble.data.psize != self.preamble.data.msize } {
            return Err(std::fmt::Error);
        }

        match u32::from_le(unsafe { self.preamble.data.msize }) {
            2048 => write!(f, "Certificate({:?})", unsafe { &self.small }),
            4096 => write!(f, "Certificate({:?})", unsafe { &self.large }),
            _ => write!(f, "Certificate({:?})", unsafe { &self.preamble }),
        }
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Certificate) -> bool {
        match unsafe { self.preamble.size() } {
            Err(_) => false,
            Ok(size) => match size {
                Size::Small => unsafe { self.small == other.small },
                Size::Large => unsafe { self.large == other.large },
            },
        }
    }
}

impl codicon::Decoder for Certificate {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        let p = Preamble {
            ver: 1u32.to_le(),
            data: reader.load()?,
        };
        match p.size()? {
            Size::Small => Ok(Certificate {
                small: Contents::decode(reader, p)?,
            }),
            Size::Large => Ok(Certificate {
                large: Contents::decode(reader, p)?,
            }),
        }
    }
}

impl codicon::Encoder for Certificate {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        match unsafe { self.preamble.size()? } {
            Size::Small => writer.save(unsafe { &self.small }),
            Size::Large => writer.save(unsafe { &self.large }),
        }
    }
}

#[cfg(feature = "openssl")]
impl codicon::Encoder<super::Body> for Certificate {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: super::Body) -> Result<()> {
        match unsafe { self.preamble.size()? } {
            Size::Small => writer.save(unsafe { &self.small.body }),
            Size::Large => writer.save(unsafe { &self.large.body }),
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<Certificate> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: Certificate) -> Result<Self> {
        let sig = match unsafe { value.preamble.size()? } {
            Size::Small => unsafe { &value.small.signature[..] },
            Size::Large => unsafe { &value.large.signature[..] },
        };

        Ok(Self {
            id: Some(unsafe { value.preamble.data.sid }),
            sig: sig.iter().rev().cloned().collect(),
            kind: pkey::Id::RSA,
            hash: hash::MessageDigest::sha256(),
            usage: Usage::ARK.into(),
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<Certificate> for PublicKey<Usage> {
    type Error = Error;

    #[inline]
    fn try_from(v: Certificate) -> Result<Self> {
        let (n, e) = match unsafe { v.preamble.size()? } {
            Size::Small => unsafe { (&v.small.body.modulus[..], &v.small.body.pubexp[..]) },

            Size::Large => unsafe { (&v.large.body.modulus[..], &v.large.body.pubexp[..]) },
        };

        let key = pkey::PKey::from_rsa(rsa::Rsa::from_public_components(
            bn::BigNum::from_le(n)?,
            bn::BigNum::from_le(e)?,
        )?)?;

        Ok(Self {
            usage: unsafe { v.preamble.data.usage },
            hash: hash::MessageDigest::sha256(),
            id: Some(unsafe { v.preamble.data.kid }),
            key,
        })
    }
}
