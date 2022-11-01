// SPDX-License-Identifier: Apache-2.0

use crate::backend::{Backend, Signatures};
use crate::exec::{open_wasm, run_package, EXECS};

use std::fmt::Debug;
use std::fs::read_to_string;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;

use anyhow::anyhow;
use camino::Utf8PathBuf;
use clap::Args;
use enarx_config::{Config, PartialConfig};
use enarx_exec_wasmtime::Package;

/// Run a WebAssembly module inside an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_BACKEND")]
    pub backend: Option<&'static dyn Backend>,

    #[clap(long, env = "ENARX_WASMCFGFILE")]
    pub wasmcfgfile: Option<Utf8PathBuf>,

    #[clap(long)]
    pub with_steward: Option<String>,

    #[clap(long)]
    pub with_args: Option<String>,

    #[clap(long)]
    pub with_files: Option<String>,

    #[clap(long)]
    pub with_env: Option<String>,

    /// Path of the WebAssembly module to run
    #[clap(value_name = "MODULE")]
    pub module: Utf8PathBuf,

    /// Start an unsigned Keep
    #[clap(long)]
    pub unsigned: bool,

    /// Path of the signature file to use.
    #[clap(long, value_name = "SIGNATURES")]
    pub signatures: Option<Utf8PathBuf>,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[clap(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let Self {
            backend,
            wasmcfgfile,
            with_steward,
            with_args,
            with_files,
            with_env,
            module,
            unsigned,
            signatures,
            #[cfg(feature = "gdb")]
            gdblisten,
        } = self;

        let mut config = match wasmcfgfile {
            Some(path) => toml::from_str(&read_to_string(path)?)?,
            None => Config::default(),
        };

        let partial_config = PartialConfig::new(with_steward, with_args, with_files, with_env)?;
        if let Some(keys) = partial_config {
            config.update(keys);
        }

        let backend = backend.unwrap_or_default();
        let exec = EXECS
            .iter()
            .find(|w| w.with_backend(backend))
            .ok_or_else(|| anyhow!("no supported exec found"))
            .map(|b| b.exec())?;

        let signatures = if unsigned {
            None
        } else {
            Signatures::load(signatures)?
        };

        let get_pkg = || {
            let wasm = open_wasm(module)?;

            let package = Package::Local {
                #[cfg(unix)]
                wasm: wasm.into_raw_fd(),
                #[cfg(windows)]
                wasm,
                config,
            };

            Ok(package)
        };

        let code = run_package(
            backend,
            exec,
            signatures,
            #[cfg(not(feature = "gdb"))]
            None,
            #[cfg(feature = "gdb")]
            Some(gdblisten),
            get_pkg,
        )?;

        std::process::exit(code);
    }
}
