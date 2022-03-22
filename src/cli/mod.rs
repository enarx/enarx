// SPDX-License-Identifier: Apache-2.0

mod exec;
mod info;
mod log;
mod run;
#[cfg(feature = "backend-sgx")]
pub mod sgx;
#[cfg(feature = "backend-sev")]
pub mod snp;

use anyhow::{anyhow, Result};
use std::ops::Deref;
use structopt::{clap::AppSettings, StructOpt};

pub use self::log::LogOptions;

/// `enarx` subcommands and their options/arguments.
#[derive(StructOpt, Debug)]
pub enum Command {
    Info(info::Options),
    #[structopt(setting(AppSettings::Hidden))]
    Exec(exec::Options),
    Run(run::Options),
    #[cfg(feature = "backend-sev")]
    Snp(snp::Command),
    #[cfg(feature = "backend-sgx")]
    Sgx(sgx::Command),
}

//
// Options & shared setup code for backends/shims
//

use crate::backend::{Backend, BACKENDS};

#[derive(StructOpt, Debug)]
pub struct BackendOptions {
    /// Set which backend to use
    #[structopt(long, env = "ENARX_BACKEND")]
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

//
// Options & shared setup code for workldr
//
use crate::workldr::{Workldr, WORKLDRS};

#[derive(StructOpt, Debug)]
pub struct WorkldrOptions {
    #[structopt(long, env = "ENARX_WASMCFGFILE")]
    pub wasmcfgfile: Option<String>,
    // FUTURE: Path to an external workldr binary
}

impl WorkldrOptions {
    pub fn pick(&self) -> Result<&dyn Workldr> {
        WORKLDRS
            .deref()
            .iter()
            .find(|_| true)
            .ok_or_else(|| anyhow!("No supported workldr found"))
            .map(|b| &**b)
    }
}
