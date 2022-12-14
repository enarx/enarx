// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use std::fs::OpenOptions;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Fetch a URL and save the contents as the hash of the URL
pub fn save_file(url: &str, dest: &Path) -> anyhow::Result<()> {
    let mut response = ureq::get(url)
        .call()
        .context(format!("retrieving CRL {url} from server"))?
        .into_reader();

    let mut dest = dest.to_path_buf();
    dest.push(hex::encode(Sha256::digest(url)));

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&dest)
        .context(format!(
            "opening destination file {:?} for saving CRL {url}",
            dest.display()
        ))?;

    std::io::copy(&mut response, &mut file).context(format!(
        "saving CRL {url} to destination file {:?}",
        dest.display()
    ))?;

    Ok(())
}
