// SPDX-License-Identifier: Apache-2.0

use crate::backend::Signatures;
use crate::cli::BackendOptions;
use crate::exec::{open_package, run_package, EXECS};

use std::fmt::Debug;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
use std::process::ExitCode;

use anyhow::anyhow;
use camino::Utf8PathBuf;
use clap::Args;
use enarx_exec_wasmtime::Package;

/// Run a WebAssembly module inside an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    #[clap(long, env = "ENARX_WASMCFGFILE")]
    pub wasmcfgfile: Option<Utf8PathBuf>,

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
    pub fn execute(
        self,
        #[cfg(unix)] log_level: Option<enarx_exec_wasmtime::LogLevel>,
        #[cfg(all(unix, feature = "bench"))] profile: Option<impl IntoRawFd>,
    ) -> anyhow::Result<ExitCode> {
        let Self {
            backend,
            wasmcfgfile,
            module,
            unsigned,
            signatures,
            #[cfg(feature = "gdb")]
            gdblisten,
        } = self;
        let backend = backend.pick()?;
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
            let (wasm, conf) = open_package(module, wasmcfgfile)?;

            #[cfg(unix)]
            let pkg = Package::Local {
                wasm: wasm.into_raw_fd(),
                conf: conf.map(|conf| conf.into_raw_fd()),
            };

            #[cfg(windows)]
            let pkg = Package::Local { wasm, conf };

            Ok(pkg)
        };

        run_package(
            backend,
            exec,
            signatures,
            #[cfg(not(feature = "gdb"))]
            None,
            #[cfg(feature = "gdb")]
            Some(gdblisten),
            get_pkg,
            #[cfg(unix)]
            log_level,
            #[cfg(all(unix, feature = "bench"))]
            profile,
        )
    }
}
