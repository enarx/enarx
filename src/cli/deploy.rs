// SPDX-License-Identifier: Apache-2.0

use crate::cli::BackendOptions;
use crate::drawbridge::parse_tag;
use crate::exec::{open_package, run_package, EXECS};

use std::fmt::Debug;
use std::fs;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;

use crate::backend::Signatures;
use anyhow::{anyhow, bail, Context};
use camino::Utf8PathBuf;
use clap::Args;
use enarx_exec_wasmtime::{Package, PACKAGE_CONFIG, PACKAGE_ENTRYPOINT};
use url::Url;

/// Run an Enarx package inside an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    /// URL of the package to run.
    #[clap(value_name = "PACKAGE")]
    pub package: String,

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
            package,
            signatures,
            #[cfg(feature = "gdb")]
            gdblisten,
        } = self;

        let backend = backend.pick()?;
        // TODO: Only allow secure backends
        // https://github.com/enarx/enarx/issues/1850
        let exec = EXECS
            .iter()
            .find(|w| w.with_backend(backend))
            .ok_or_else(|| anyhow!("no supported exec found"))
            .map(|b| b.exec())?;

        #[cfg(not(feature = "gdb"))]
        let gdblisten = None;

        #[cfg(feature = "gdb")]
        let gdblisten = Some(gdblisten);

        let signatures = Signatures::load(signatures)?;

        let (host, user, repo, tag) = parse_tag(&package)?;
        let addr = format!("https://{host}/api/v0.1.0/{user}/{repo}/_tag/{tag}/tree");
        let package: Url = addr
            .parse()
            .with_context(|| format!("Failed to parse URL: {addr}"))?;

        let code = match package.scheme() {
            "file" => {
                let path = package
                    .to_file_path()
                    .map_err(|()| anyhow!("failed to parse file path from URL `{}`", package))?;
                let md = fs::metadata(&path).with_context(|| {
                    format!("failed to get information about `{}`", path.display())
                })?;
                let (wasm, conf) = if md.is_file() {
                    (path, None)
                } else if md.is_dir() {
                    (
                        path.join(PACKAGE_ENTRYPOINT),
                        Some(path.join(PACKAGE_CONFIG)),
                    )
                } else {
                    bail!(
                        "no Enarx package or WASM module found at `{}`",
                        path.display()
                    )
                };

                let get_pkg = || {
                    let (wasm, conf) = open_package(wasm, conf)?;

                    #[cfg(unix)]
                    let pkg = Package::Local {
                        wasm: wasm.into_raw_fd(),
                        conf: conf.map(|conf| conf.into_raw_fd()),
                    };

                    #[cfg(windows)]
                    let pkg = Package::Local { wasm, conf };

                    Ok(pkg)
                };

                run_package(backend, exec, signatures, gdblisten, get_pkg)?
            }

            // The WASM module and config will be downloaded from a remote by exec-wasmtime
            // TODO: Disallow `http` or guard by an `--insecure` flag
            "http" | "https" => run_package(backend, exec, signatures, gdblisten, || {
                Ok(Package::Remote(package))
            })?,

            s => bail!("unsupported scheme: {}", s),
        };

        std::process::exit(code);
    }
}
