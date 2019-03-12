use endicon::Endianness;
use codicon::Decoder;
use std::io::Read;

use std::num::NonZeroU128;

use super::*;

#[derive(Copy, Clone, Debug)]
struct Internal<T>(T);

#[derive(Copy, Clone, Debug)]
struct Sev1;

#[derive(Copy, Clone, Debug)]
struct Ca1;

impl Decoder<Internal<usize>> for RsaKey {
    type Error = Error;

    #[inline]
    fn decode(reader: &mut impl Read, params: Internal<usize>) -> Result<Self, Error> {
        let psize = match params.0 {
            2048 => 2048,
            4096 => 4096,
            s => Err(Error::Invalid(format!("pubexp size: {}", s)))?,
        };

        let msize = match u32::decode(reader, Endianness::Little)? {
            2048 => 2048,
            4096 => 4096,
            s => Err(Error::Invalid(format!("modulus size: {}", s)))?,
        };

        let mut pubexp = [0u8; 4096 / 8];
        reader.read_exact(&mut &mut pubexp[..psize / 8])?;

        let mut modulus = [0u8; 4096 / 8];
        reader.read_exact(&mut &mut modulus[..msize / 8])?;

        Ok(RsaKey { pubexp, modulus })
    }
}

impl Decoder<Sev1> for Option<Usage> {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x1001 => Usage::OwnerCertificateAuthority,
            0x1002 => Usage::PlatformEndorsementKey,
            0x1003 => Usage::PlatformDiffieHellman,
            0x1004 => Usage::ChipEndorsementKey,
            0x0000 => Usage::AmdRootKey,
            0x0013 => Usage::AmdSevKey,
            0x1000 => return Ok(None),
            u => Err(Error::Invalid(format!("usage: {:08X}", u)))?
        }))
    }
}

impl Decoder<Sev1> for Option<SigAlgo> {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x0000 => return Ok(None),
            0x0001 => SigAlgo::RsaSha256,
            0x0002 => SigAlgo::EcdsaSha256,
            0x0101 => SigAlgo::RsaSha384,
            0x0102 => SigAlgo::EcdsaSha384,
            a => Err(Error::Invalid(format!("algorithm: {:08X}", a)))?
        }))
    }
}

impl Decoder<Sev1> for Option<ExcAlgo> {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x0000 => return Ok(None),
            0x0003 => ExcAlgo::EcdhSha256,
            0x0103 => ExcAlgo::EcdhSha384,
            a => Err(Error::Invalid(format!("algorithm: {:08X}", a)))?
        }))
    }
}

impl Decoder<Sev1> for Option<Algo> {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x0000 => return Ok(None),
            0x0001 => Algo::Sig(SigAlgo::RsaSha256),
            0x0002 => Algo::Sig(SigAlgo::EcdsaSha256),
            0x0003 => Algo::Exc(ExcAlgo::EcdhSha256),
            0x0101 => Algo::Sig(SigAlgo::RsaSha384),
            0x0102 => Algo::Sig(SigAlgo::EcdsaSha384),
            0x0103 => Algo::Exc(ExcAlgo::EcdhSha384),
            a => Err(Error::Invalid(format!("algorithm: {:08X}", a)))?
        }))
    }
}

impl Decoder<Sev1> for Firmware {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        Ok(Firmware(
            u8::decode(reader, Endianness::Little)?,
            u8::decode(reader, Endianness::Little)?,
        ))
    }
}

impl Decoder<Sev1> for RsaKey {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        RsaKey::decode(reader, Internal(4096))
    }
}

impl Decoder<Sev1> for Curve {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Sev1) -> Result<Self, Error> {
        Ok(match u32::decode(reader, Endianness::Little)? {
            1 => Curve::P256,
            2 => Curve::P384,
            c => Err(Error::Invalid(format!("curve: {}", c)))?
        })
    }
}

impl Decoder<Sev1> for EccKey {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Sev1) -> Result<Self, Error> {
        let c = Curve::decode(reader, params)?;

        let mut x = [0u8; 576 / 8];
        reader.read_exact(&mut x)?;

        let mut y = [0u8; 576 / 8];
        reader.read_exact(&mut y)?;

        reader.read_exact(&mut [0u8; 880])?; // Reserved

        Ok(EccKey { c, x, y })
    }
}

impl Decoder<Internal<Algo>> for Key {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Internal<Algo>) -> Result<Self, Error> {
        use self::SigAlgo::*;
        use self::ExcAlgo::*;
        use self::Algo::*;

        Ok(match params.0 {
            Sig(EcdsaSha256) => Key::Ecc(EccKey::decode(reader, Sev1)?),
            Sig(EcdsaSha384) => Key::Ecc(EccKey::decode(reader, Sev1)?),
            Exc(EcdhSha256) => Key::Ecc(EccKey::decode(reader, Sev1)?),
            Exc(EcdhSha384) => Key::Ecc(EccKey::decode(reader, Sev1)?),
            Sig(RsaSha256) => Key::Rsa(RsaKey::decode(reader, Sev1)?),
            Sig(RsaSha384) => Key::Rsa(RsaKey::decode(reader, Sev1)?),
        })
    }
}

impl Decoder<Sev1> for PublicKey {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Sev1) -> Result<Self, Error> {
        let usage = match Option::decode(reader, params)? {
            None => Err(Error::Invalid("public key usage".to_string()))?,
            Some(u) => u,
        };

        let algo = match Option::decode(reader, params)? {
            None => Err(Error::Invalid("public key algorithm".to_string()))?,
            Some(a) => a,
        };

        let key = Key::decode(reader, Internal(algo))?;

        Ok(PublicKey { usage, algo, key, id: None })
    }
}

impl Decoder<Sev1> for Option<Signature> {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Sev1) -> Result<Self, Error> {
        let usage = Option::decode(reader, params)?;
        let algo = Option::decode(reader, params)?;

        let mut sig = [0u8; 4096 / 8];
        reader.read_exact(&mut &mut sig[..])?;

        if let Some(usage) = usage {
            if let Some(algo) = algo {
                return Ok(Some(Signature { usage, algo, sig, id: None }));
            }
        }

        Ok(None)
    }
}

impl Decoder<Sev1> for Certificate {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Sev1) -> Result<Self, Error> {
        let firmware = Firmware::decode(reader, Sev1)?;

        u8::decode(reader, Endianness::Little)?; // Reserved
        u8::decode(reader, Endianness::Little)?; // Reserved

        let key = PublicKey::decode(reader, params)?;

        let sigs = [
            Option::decode(reader, params)?,
            Option::decode(reader, params)?
        ];

        Ok(Certificate { version: 1, firmware: Some(firmware), key, sigs })
    }
}

impl Decoder<Ca1> for RsaKey {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Ca1) -> Result<Self, Error> {
        let psize = u32::decode(reader, Endianness::Little)?;
        RsaKey::decode(reader, Internal(psize as usize))
    }
}

impl Decoder<Ca1> for Option<NonZeroU128> {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Ca1) -> Result<Self, Error> {
        Ok(NonZeroU128::new(u128::decode(reader, Endianness::Little)?))
    }
}

impl Decoder<Ca1> for Certificate {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Ca1) -> Result<Self, Error> {
        let key_id = Option::<NonZeroU128>::decode(reader, Ca1)?;
        let sig_id = Option::<NonZeroU128>::decode(reader, Ca1)?;

        let usage = match Option::decode(reader, Sev1)? {
            Some(Usage::AmdRootKey) => Usage::AmdRootKey,
            Some(Usage::AmdSevKey) => Usage::AmdSevKey,
            u => Err(Error::Invalid(format!("usage: {:?}", u)))?,
        };

        u128::decode(reader, Endianness::Little)?; // Reserved

        let key = RsaKey::decode(reader, Ca1)?;

        let mut sig = [0u8; 4096 / 8];
        reader.read_exact(&mut &mut sig[..key.msize()?])?;

        Ok(Certificate {
            version: 1,
            firmware: None,
            key: PublicKey {
                algo: Algo::Sig(SigAlgo::RsaSha256),
                key: Key::Rsa(key),
                id: key_id,
                usage,
            },
            sigs: [
                Some(Signature {
                    usage: Usage::AmdRootKey,
                    algo: SigAlgo::RsaSha256,
                    id: sig_id,
                    sig,
                }),
                None
            ]
        })
    }
}

impl Decoder<Kind> for Certificate {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Kind) -> Result<Self, Error> {
        Ok(match params {
            Kind::Sev => {
                match u32::decode(reader, Endianness::Little)? {
                    1 => Certificate::decode(reader, Sev1),
                    v => Err(Error::Invalid(format!("version: {}", v))),
                }
            },

            Kind::Ca => {
                match u32::decode(reader, Endianness::Little)? {
                    1 => Certificate::decode(reader, Ca1),
                    v => Err(Error::Invalid(format!("version: {}", v))),
                }
            },
        }?)
    }
}
