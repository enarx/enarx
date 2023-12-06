// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::iter::zip;
use std::vec;

use anyhow::Context;
use der::{Decode, Encode, Sequence};
use x509_cert::crl::CertificateList;
use x509_cert::time::Time;

#[derive(Sequence)]
pub struct CrlListEntry {
    pub url: String,
    pub crl: CertificateList,
}

impl From<(String, CertificateList)> for CrlListEntry {
    fn from((url, crl): (String, CertificateList)) -> Self {
        Self { url, crl }
    }
}

impl From<CrlListEntry> for (String, CertificateList) {
    fn from(CrlListEntry { url, crl }: CrlListEntry) -> Self {
        (url, crl)
    }
}

#[derive(Sequence)]
pub struct CrlList {
    pub crls: Vec<CrlListEntry>,
}

impl<'a> FromIterator<(String, CertificateList)> for CrlList {
    fn from_iter<T: IntoIterator<Item = (String, CertificateList)>>(crls: T) -> Self {
        let crls = crls.into_iter().map(Into::into).collect();
        Self { crls }
    }
}

impl CrlList {
    pub fn entries(&self) -> impl Iterator<Item = (&str, &CertificateList)> {
        self.crls
            .iter()
            .map(|CrlListEntry { url, crl }| (url.as_str(), crl))
    }

    pub fn next_update(&self) -> Option<Time> {
        let first = self.crls.first()?;
        let mut first = first.crl.tbs_cert_list.next_update?;

        for crl in self.crls.iter() {
            if let Some(next) = crl.crl.tbs_cert_list.next_update {
                if next.to_system_time() < first.to_system_time() {
                    first = next;
                }
            }
        }

        Some(first)
    }
}

/// Maximum length of the CRL in bytes
const MAX_CRL_SIZE: u64 = 10000;

/// Fetches CRLs from each url within `urls` and returns pairs of CRLs and URLs they originated
/// from concatenated in a DER sequence.
pub fn fetch_crl_list<const N: usize>(urls: [String; N]) -> anyhow::Result<Vec<u8>> {
    let mut resps = Vec::with_capacity(N);
    for url in &urls {
        let mut crl = vec![];
        ureq::get(url)
            .call()
            .with_context(|| format!("failed to connect to `{url}`"))?
            .into_reader()
            .take(MAX_CRL_SIZE)
            .read_to_end(&mut crl)
            .with_context(|| format!("failed to read response from `{url}`"))?;
        resps.push(crl);
    }
    let mut crls = Vec::with_capacity(N);
    for (i, resp) in resps.iter().enumerate() {
        let crl = CertificateList::from_der(resp)
            .with_context(|| format!("failed to decode CRL fetched from `{}`", urls[i]))?;
        crls.push(crl)
    }
    zip(urls, crls)
        .collect::<CrlList>()
        .to_der()
        .context("failed to encode CRL list")
}
