// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;

use anyhow::{Error, Result};
use sgx::page::SecInfo;

pub struct Hasher(sgx::signature::Hasher<sgx::crypto::openssl::S256Digest>);

impl TryFrom<super::config::Config> for Hasher {
    type Error = Error;

    #[inline]
    fn try_from(config: super::config::Config) -> Result<Self> {
        Ok(Self(sgx::signature::Hasher::new(config.size, config.ssap)))
    }
}

impl super::super::Mapper for Hasher {
    type Config = super::config::Config;
    type Output = Vec<u8>;

    #[inline]
    fn map(
        &mut self,
        pages: mmarinus::Map<mmarinus::perms::ReadWrite>,
        to: usize,
        with: (SecInfo, bool),
    ) -> anyhow::Result<()> {
        self.0.load(&*pages, to, with.0, with.1).unwrap();
        Ok(())
    }
}

impl TryFrom<Hasher> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(hasher: Hasher) -> Result<Self> {
        Ok(hasher.0.finish().into())
    }
}
