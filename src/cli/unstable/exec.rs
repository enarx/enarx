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

    /// Binary to load and run inside the keep
    #[clap(value_name = "BINARY")]
    pub binpath: Utf8PathBuf,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[clap(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}

#[cfg(enarx_with_shim)]
impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        use crate::exec::keep_exec;
        use mmarinus::{perms, Map, Private};

        let backend = self.backend.pick()?;
        let binary = Map::load(&self.binpath, Private, perms::Read)?;

        #[cfg(not(feature = "gdb"))]
        let gdblisten = None;

        #[cfg(feature = "gdb")]
        let gdblisten = Some(self.gdblisten);

        let exit_code = keep_exec(backend, backend.shim(), binary, None, gdblisten)?;
        std::process::exit(exit_code);
    }
}
