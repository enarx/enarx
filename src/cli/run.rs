// SPDX-License-Identifier: Apache-2.0

use crate::cli::BackendOptions;
use crate::exec::{open_package, run_package, EXECS};

use std::fmt::Debug;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
use std::path::PathBuf;

use anyhow::anyhow;
use clap::Args;
use enarx_exec_wasmtime::Package;

/// Run a WebAssembly module inside an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    #[clap(long, env = "ENARX_WASMCFGFILE")]
    pub wasmcfgfile: Option<PathBuf>,

    /// Path of the WebAssembly module to run
    #[clap(value_name = "MODULE", parse(from_os_str))]
    pub module: PathBuf,

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
            module,
            #[cfg(feature = "gdb")]
            gdblisten,
        } = self;
        let backend = backend.pick()?;
        let exec = EXECS
            .iter()
            .find(|w| w.with_backend(backend))
            .ok_or_else(|| anyhow!("no supported exec found"))
            .map(|b| b.exec())?;

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

        let code = run_package(
            backend,
            exec,
            #[cfg(not(feature = "gdb"))]
            None,
            #[cfg(feature = "gdb")]
            Some(gdblisten),
            get_pkg,
        )?;
        std::process::exit(code);
    }
}
