// SPDX-License-Identifier: Apache-2.0

use super::{BackendOptions, Result, StructOpt, WorkldrOptions};
use anyhow::bail;

use std::{fmt::Debug, path::PathBuf};

/// Run a WebAssembly module inside an Enarx Keep.
#[derive(StructOpt, Debug)]
pub struct Options {
    #[structopt(flatten)]
    pub backend: BackendOptions,

    #[structopt(flatten)]
    pub workldr: WorkldrOptions,

    /// Set a WASI environment variable
    #[structopt(
        short = "e",
        long = "env",
        number_of_values = 1,
        value_name = "NAME=VAL",
        parse(try_from_str=parse_env_var),
    )]
    pub envs: Vec<(String, String)>,

    // TODO: --stdin, --stdout, --stderr
    /// Path of the WebAssembly module to run
    #[structopt(value_name = "MODULE", parse(from_os_str))]
    pub module: PathBuf,

    /// Arguments to pass to the WebAssembly module
    #[structopt(value_name = "ARGS", last = true)]
    pub args: Vec<String>,
}

fn parse_env_var(s: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        bail!("must be of the form `NAME=VAL`");
    }
    Ok((parts[0].to_owned(), parts[1].to_owned()))
}
