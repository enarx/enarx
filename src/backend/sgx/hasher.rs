// SPDX-License-Identifier: Apache-2.0

use super::config::Config;

use std::convert::TryFrom;

use anyhow::{Error, Result};
use mmarinus::{perms, Map};
use sgx::crypto::rcrypto::S256Digest;
use sgx::page::SecInfo;
use sgx::signature::Body;
use sgx::signature::Hasher as SgxHasher;

pub struct Hasher {
    digest: SgxHasher<S256Digest>,
    cnfg: Config,
}

impl TryFrom<Config> for Hasher {
    type Error = Error;

    #[inline]
    fn try_from(config: Config) -> Result<Self> {
        Ok(Self {
            digest: sgx::signature::Hasher::new(config.size, config.ssap),
            cnfg: config,
        })
    }
}

impl super::super::Mapper for Hasher {
    type Config = Config;
    type Output = Vec<u8>;

    #[inline]
    fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
        with: (SecInfo, bool),
    ) -> anyhow::Result<()> {
        self.digest.load(&pages, to, with.0, with.1).unwrap();
        Ok(())
    }
}

impl TryFrom<Hasher> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(hasher: Hasher) -> Result<Self> {
        let body = hasher.cnfg.parameters.body(hasher.digest.finish());

        // Safety: We know that the body is sized and u8 does not need alignment.
        Ok(unsafe {
            core::slice::from_raw_parts(
                &body as *const _ as *const u8,
                core::mem::size_of::<Body>(),
            )
        }
        .to_vec())
    }
}
