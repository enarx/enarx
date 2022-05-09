// SPDX-License-Identifier: Apache-2.0

mod exec;
mod info;
mod log;
pub mod run;
#[cfg(enarx_with_shim)]
pub mod sgx;
#[cfg(enarx_with_shim)]
pub mod snp;

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use std::ops::Deref;

pub use self::log::LogOptions;

/// `enarx` subcommands and their options/arguments.
#[derive(Subcommand, Debug)]
pub enum Command {
    Info(info::Options),
    #[clap(hide = true)]
    Exec(exec::Options),
    Run(run::Options),
    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Snp(snp::Command),
    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Sgx(sgx::Command),
}

//
// Options & shared setup code for backends/shims
//

use crate::backend::{Backend, BACKENDS};

#[derive(Args, Debug)]
pub struct BackendOptions {
    /// Set which backend to use
    #[clap(long, env = "ENARX_BACKEND")]
    backend: Option<String>,
    // TODO: Path to an external shim binary?
    //shim: Option<PathBuf>,
}

impl BackendOptions {
    pub fn pick(&self) -> Result<&dyn Backend> {
        if let Some(ref name) = self.backend {
            BACKENDS
                .deref()
                .iter()
                .find(|b| b.have() && b.name() == name)
                .ok_or_else(|| anyhow!("Keep backend {:?} is unsupported.", name))
        } else {
            BACKENDS.deref().iter().find(|b| b.have()).ok_or_else(|| {
                anyhow!(
                    "No supported backend found. Please check your machine with `$ enarx info`."
                )
            })
        }
        .map(|b| &**b)
    }
}
