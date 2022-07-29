// SPDX-License-Identifier: Apache-2.0

use super::config::Config;
use super::snp::launch::linux::SEV_SNP_VMSA_SHA384;
use super::snp::launch::PageInfo;
use super::snp::launch::PageType;
use crate::backend::ByteSized;

use std::convert::TryFrom;

use anyhow::Error;
use mmarinus::{perms, Map};
use primordial::Page;
use ring::digest;
use sallyport::elf::pf::snp::{CPUID, SECRETS};

pub struct Hasher {
    pub config: Config,
    pub digest: [u8; 48],
}

impl TryFrom<Config> for Hasher {
    type Error = Error;

    fn try_from(config: Config) -> anyhow::Result<Self> {
        Ok(Hasher {
            config,
            digest: [0u8; 48],
        })
    }
}

impl Hasher {
    pub fn update(&mut self, page_type: PageType, to: usize, src: Option<&[u8]>) {
        let mut page_info = PageInfo {
            digest_cur: self.digest,
            page_type: page_type as _,
            gpa: to as u64,
            ..Default::default()
        };

        if let Some(src) = src {
            assert_eq!(src.len(), Page::SIZE);
            let page_digest = digest::digest(&digest::SHA384, src);
            page_info.contents.copy_from_slice(page_digest.as_ref());
        }

        let page_info_digest = digest::digest(&digest::SHA384, page_info.as_bytes());
        self.digest.copy_from_slice(page_info_digest.as_ref());
    }

    pub fn update_finish(&mut self) {
        let page_info = PageInfo {
            digest_cur: self.digest,
            page_type: PageType::Vmsa as _,
            gpa: 0xFFFFFFFFF000,
            contents: SEV_SNP_VMSA_SHA384,
            ..Default::default()
        };

        let page_info_digest = digest::digest(&digest::SHA384, page_info.as_bytes());
        self.digest.copy_from_slice(page_info_digest.as_ref());
    }
}

impl Hasher {
    pub(crate) fn hash(&mut self, pages: &[u8], to: usize, with: u32) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        if with & CPUID != 0 {
            assert_eq!(pages.len(), Page::SIZE);
            self.update(PageType::Cpuid, to, None);
        } else if with & SECRETS != 0 {
            assert_eq!(pages.len(), Page::SIZE);
            self.update(PageType::Secrets, to, None);
        } else {
            for (i, page) in pages.chunks(Page::SIZE).enumerate() {
                self.update(PageType::Normal, to + i * Page::SIZE, Some(page));
            }
        };

        Ok(())
    }
}

impl super::super::Mapper for Hasher {
    type Config = Config;
    type Output = Vec<u8>;

    fn map(&mut self, pages: Map<perms::ReadWrite>, to: usize, with: u32) -> anyhow::Result<()> {
        self.hash(pages.as_ref(), to, with)
    }
}

impl TryFrom<Hasher> for Vec<u8> {
    type Error = Error;
    fn try_from(mut hasher: Hasher) -> anyhow::Result<Self> {
        hasher.update_finish();

        let id_block = hasher.config.id_block_from_digest(hasher.digest);

        Ok(id_block.as_bytes().into())
    }
}
