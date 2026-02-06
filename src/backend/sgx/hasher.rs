// SPDX-License-Identifier: Apache-2.0

use super::config::Config;

use std::convert::TryFrom;

use anyhow::{Context, Error, Result};
use primordial::Page;
use sgx::crypto::rcrypto::S256Digest;
use sgx::page::SecInfo;
use sgx::signature::Body;
use sgx::signature::Hasher as SgxHasher;
use vm_memory::{Bytes, MmapRegion, VolatileMemory};

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
    fn map(&mut self, pages: MmapRegion, to: usize, with: (SecInfo, bool)) -> anyhow::Result<()> {
        if pages.is_empty() {
            return Ok(());
        }

        assert_eq!(pages.len() % Page::SIZE, 0);
        let mut page_buf = [0u8; Page::SIZE];
        let mut offset = 0;
        while offset < pages.len() {
            let page_slice = pages
                .get_slice(offset, Page::SIZE)
                .context("Failed to map SGX page")?;
            page_slice
                .read_slice(&mut page_buf, 0)
                .context("Failed to read SGX page")?;
            self.digest
                .load(&page_buf, to + offset, with.0, with.1)
                .unwrap();
            offset += Page::SIZE;
        }
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
