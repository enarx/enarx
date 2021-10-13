// SPDX-License-Identifier: Apache-2.0

mod exec;
mod info;
mod log;
mod run;

use anyhow::{anyhow, Result};
use structopt::StructOpt;

pub use self::log::LogOptions;

/// `enarx` subcommands and their options/arguments.
#[derive(StructOpt, Debug)]
pub enum Command {
    Info(info::Options),
    Exec(exec::Options),
    Run(run::Options),
}

//
// Options & shared setup code for backends/shims
//

use crate::backend::{builtin_backends, Backend};

#[derive(StructOpt, Debug)]
pub struct BackendOptions {
    /// Set which backend to use
    #[structopt(long, env = "ENARX_BACKEND")]
    backend: Option<String>,
    // TODO: Path to an external shim binary?
    //shim: Option<PathBuf>,
}

impl BackendOptions {
    ///
    pub fn pick(&self) -> Result<&dyn Backend> {
        let backends = builtin_backends();

        if let Some(ref name) = self.backend {
            backends
                .iter()
                .find(|b| b.have() && b.name() == name)
                .ok_or_else(|| anyhow!("Keep backend {:?} is unsupported", name))
        } else {
            backends
                .iter()
                .find(|b| b.have())
                .ok_or_else(|| anyhow!("No supported backend found"))
        }
        .map(|b| &**b)
    }
}

//
// Options & shared setup code for workldr
//
use crate::workldr::{builtin_workldrs, Workldr};

#[derive(StructOpt, Debug)]
pub struct WorkldrOptions {
    // TODO: Path to an external workldr binary
//workldr: Option<PathBuf>,
}

impl WorkldrOptions {
    pub fn pick(&self) -> Result<&dyn Workldr> {
        let workldrs = builtin_workldrs();

        workldrs
            .iter()
            .find(|_| true)
            .ok_or_else(|| anyhow!("No supported workldr found"))
            .map(|b| &**b)
    }
}
