// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::vcek::{get_vcek_reader_with_paths, paths, UpdateMode};

use clap::Args;

/// Download the VCEK certificate for this platform.
///
/// The certificate will be saved to a cache file in
/// `/var/cache/amd-sev/` or `$XDG_CACHE_HOME` or `$HOME/.cache/`
#[derive(Args, Debug)]
// TODO: add option to let user select location to save file to
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        // try to write to the system level path first and fallback to home dir
        let mut paths = paths();
        paths.reverse();
        get_vcek_reader_with_paths(paths, UpdateMode::ReadWrite)?;
        Ok(())
    }
}
