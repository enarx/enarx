// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs, unused_variables)] // This is a work-in-progress, so...

use structopt::{clap::AppSettings, StructOpt};

use anyhow::{bail, Result};
use std::path::PathBuf;

// The main StructOpt for running `wasmldr` directly
#[derive(StructOpt, Debug)]
#[structopt(setting=AppSettings::TrailingVarArg)]
pub struct RunOptions {
    /// Pass an environment variable to the program
    #[structopt(
        short = "e",
        long = "env",
        number_of_values = 1,
        value_name = "NAME=VAL",
        parse(try_from_str=parse_env_var),
    )]
    pub envs: Vec<(String, String)>,

    // TODO: --inherit-env
    // TODO: --stdin, --stdout, --stderr
    /// Path of the WebAssembly module to run
    #[structopt(index = 1, required = true, value_name = "MODULE", parse(from_os_str))]
    pub module: PathBuf,

    // NOTE: this has to come last for TrailingVarArg
    /// Arguments to pass to the WebAssembly module
    #[structopt(value_name = "ARGS")]
    pub args: Vec<String>,
}

fn parse_env_var(s: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        bail!("must be of the form `NAME=VAL`");
    }
    Ok((parts[0].to_owned(), parts[1].to_owned()))
}
