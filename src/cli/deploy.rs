// SPDX-License-Identifier: Apache-2.0

use crate::backend::{Backend, Signatures};
use crate::drawbridge::parse_tag;
use crate::exec::{open_wasm, run_package, EXECS};

use std::fmt::Debug;
use std::fs::{self, read_to_string};
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;

use anyhow::{anyhow, bail, Context};
use camino::Utf8PathBuf;
use clap::Args;
use enarx_config::Config;
use enarx_exec_wasmtime::{Package, PACKAGE_CONFIG, PACKAGE_ENTRYPOINT};
use url::Url;

/// Deploy an Enarx package to an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(long, env = "ENARX_BACKEND")]
    pub backend: Option<&'static dyn Backend>,

    /// Package slug or a URL to deploy.
    #[clap(value_name = "PACKAGE")]
    pub package: String,

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
            package,
            unsigned,
            signatures,
            #[cfg(feature = "gdb")]
            gdblisten,
        } = self;

        let backend = backend.unwrap_or_default();
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

        let signatures = if unsigned {
            None
        } else {
            Signatures::load(signatures)?
        };

        let package = match package
            .parse()
            .ok()
            .filter(|url: &Url| !url.cannot_be_a_base())
        {
            None => {
                use drawbridge_client::API_VERSION;

                let (host, user, repo, tag) = parse_tag(&package)
                    .with_context(|| format!("failed to parse `{package}` as a Drawbridge slug"))?;
                format!("https://{host}/api/v{API_VERSION}/{user}/{repo}/_tag/{tag}")
                    .parse()
                    .with_context(|| {
                        format!("failed to construct a URL from Drawbridge slug `{package}`")
                    })?
            }
            Some(url) => url,
        };

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
                        path.join(PACKAGE_ENTRYPOINT.as_str()),
                        Some(path.join(PACKAGE_CONFIG.as_str())),
                    )
                } else {
                    bail!(
                        "no Enarx package or WASM module found at `{}`",
                        path.display()
                    )
                };

                let config = match conf {
                    Some(path) => toml::from_str(&read_to_string(path)?)?,
                    None => Config::default(),
                };

                let get_pkg = || {
                    let wasm = open_wasm(wasm)?;

                    let package = Package::Local {
                        #[cfg(unix)]
                        wasm: wasm.into_raw_fd(),
                        #[cfg(windows)]
                        wasm,
                        config,
                    };

                    Ok(package)
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
