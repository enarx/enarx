// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;

use anyhow::bail;
use clap::Args;
use enarx_config::CONFIG_TEMPLATE;

/// Generate an `Enarx.toml` template
#[derive(Args, Debug)]
pub struct Options;

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let enarx_toml_path = Path::new("Enarx.toml");
        if enarx_toml_path.exists() {
            bail!("{enarx_toml_path:?} does already exist.");
        }

        let mut enarx_toml = OpenOptions::new()
            .create(true)
            .write(true)
            .open(enarx_toml_path)?;

        enarx_toml.write_all(CONFIG_TEMPLATE.as_bytes())?;
        Ok(())
    }
}
