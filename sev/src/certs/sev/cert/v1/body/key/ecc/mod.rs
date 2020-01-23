// SPDX-License-Identifier: Apache-2.0

pub mod group;

#[cfg(feature = "openssl")]
use super::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PubKey {
    g: group::Group,
    x: [u8; 72],
    y: [u8; 72],
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "PubKey {{ group: {:?}, x: {:?}, y: {:?} }}",
            self.g,
            self.x.iter(),
            self.y.iter()
        )
    }
}

impl Eq for PubKey {}
impl PartialEq for PubKey {
    fn eq(&self, other: &PubKey) -> bool {
        self.g == other.g && self.x[..] == other.x[..] && self.y[..] == other.y[..]
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&PubKey> for ec::EcKey<pkey::Public> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        let s = value.g.size()?;
        Ok(ec::EcKey::from_public_key_affine_coordinates(
            &*ec::EcGroup::try_from(value.g)?,
            &*bn::BigNum::from_le(&value.x[..s])?,
            &*bn::BigNum::from_le(&value.y[..s])?,
        )?)
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&PubKey> for pkey::PKey<pkey::Public> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        Ok(pkey::PKey::from_ec_key(value.try_into()?)?)
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&ec::EcKey<pkey::Private>> for PubKey {
    type Error = Error;

    fn try_from(value: &ec::EcKey<pkey::Private>) -> Result<Self> {
        let g = value.group();
        let mut c = bn::BigNumContext::new()?;
        let mut x = bn::BigNum::new()?;
        let mut y = bn::BigNum::new()?;

        value
            .public_key()
            .affine_coordinates_gfp(g, &mut x, &mut y, &mut c)?;
        Ok(Self {
            g: group::Group::try_from(g)?,
            x: x.into_le(),
            y: y.into_le(),
        })
    }
}

#[cfg(feature = "openssl")]
impl PubKey {
    pub fn generate(group: group::Group) -> Result<(Self, ec::EcKey<pkey::Private>)> {
        let grp: ec::EcGroup = group.try_into()?;
        let prv = ec::EcKey::generate(&*grp)?;
        Ok((Self::try_from(&prv)?, prv))
    }
}
