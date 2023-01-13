// SPDX-License-Identifier: Apache-2.0

use crate::cli::BackendOptions;

use camino::Utf8PathBuf;
use clap::Args;

/// Execute a (static, PIE) binary inside an Enarx Keep.
///
/// The binary must be a statically linked position-independent executable,
/// compiled with flags like `-nostdlib -static-pie -fPIC`. No commandline
/// arguments are passed, the program's `argv[0]` will be `/init`, and the
/// environment is empty except for `LANG=C`.
///
/// This subcommand is hidden from the main help because it's unlikely to be
/// useful because of the restrictions above. It's mainly used for
/// development and integration tests.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    /// Shim to load and run
    #[clap(long, value_name = "SHIM")]
    pub shim: Option<Utf8PathBuf>,

    /// Binary to load and run inside the keep
    #[clap(value_name = "BINARY")]
    pub binpath: Utf8PathBuf,

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

#[cfg(enarx_with_shim)]
impl Options {
    pub fn execute(self) -> anyhow::Result<std::process::ExitCode> {
        use crate::backend::Signatures;

        let Self {
            backend,
            shim,
            binpath,
            unsigned,
            signatures,
            #[cfg(feature = "gdb")]
            gdblisten,
        } = self;

        use crate::exec::keep_exec;
        use mmarinus::{perms, Map, Private};

        let backend = backend.pick()?;
        let binary = Map::load(binpath, Private, perms::Read)?;
        let shim = if let Some(shim) = shim {
            Some(Map::load(shim, Private, perms::Read)?)
        } else {
            None
        };

        let signatures = if unsigned {
            None
        } else {
            Signatures::load(signatures)?
        };

        #[cfg(not(feature = "gdb"))]
        let gdblisten = None;

        #[cfg(feature = "gdb")]
        let gdblisten = Some(gdblisten);

        keep_exec(
            backend,
            shim.as_ref().map(|t| t.as_ref()).unwrap_or(backend.shim()),
            binary,
            signatures,
            gdblisten,
        )
    }
}
