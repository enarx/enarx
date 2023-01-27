// SPDX-License-Identifier: Apache-2.0

mod config;
mod deploy;
#[cfg(enarx_with_shim)]
mod key;
mod package;
mod platform;
mod repo;
mod run;
#[cfg(enarx_with_shim)]
mod sign;
mod tree;
mod unstable;
mod user;

#[cfg(enarx_with_shim)]
use crate::backend::probe::x86_64::Vendor;
use crate::backend::{Backend, BACKENDS};

use std::io;
use std::ops::Deref;
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{anyhow, bail};
use clap::{Args, Parser, Subcommand};
use tracing::info;
use tracing_subscriber::filter::{filter_fn, FilterExt};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Tool to deploy WebAssembly into Enarx Keeps
///
/// Enarx is a tool for running Webassembly inside an Enarx Keep
/// - that is a hardware isolated environment using technologies
/// such as Intel SGX or AMD SEV.
///
/// For more information about the project and the technology used
/// visit the Enarx Project home page https://enarx.dev/.
#[derive(Parser, Debug)]
#[clap(version)]
pub struct Options {
    /// Logging options
    #[clap(flatten)]
    logger: LogOptions,

    /// Subcommands (with their own options)
    #[clap(subcommand)]
    cmd: Subcommands,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let env_filter = EnvFilter::builder()
            .parse_lossy(self.logger.log_filter.as_ref().unwrap_or(&"".to_owned()));
        #[cfg(unix)]
        let log_level = env_filter
            .max_level_hint()
            .and_then(tracing_subscriber::filter::LevelFilter::into_level)
            .map(Into::into);

        let target_filter = filter_fn(|meta| {
            let target = meta.target();
            [
                "enarx",
                "enarx_exec_wasmtime",
                "enarx_shim_kvm",
                "enarx_shim_sgx",
                #[cfg(feature = "dbg")]
                "rustls",
                #[cfg(feature = "dbg")]
                "wasi_common",
            ]
            .into_iter()
            .any(|name| target.eq(name) || target.starts_with(&format!("{name}::")))
        });
        let log_filter = env_filter.and(target_filter);

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || -> Box<dyn io::Write> {
                match self.logger.log_target {
                    LogTarget::Stdout => Box::new(io::stdout()),
                    LogTarget::Stderr => Box::new(io::stderr()),
                }
            })
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_filter(log_filter);

        #[cfg(feature = "bench")]
        let (flame_layer, _guard, profile) = if let Some(ref profile) = self.logger.profile {
            use std::fs::File;

            use anyhow::Context;

            // Open `/dev/null` to reserve fd 3 on Unix, which `exec-wasmtime` will expect to read config from
            // It will be dropped at the end of this block, freeing it for the following socketpair call
            #[cfg(unix)]
            let _reserved = matches!(self.cmd, Subcommands::Run(_) | Subcommands::Deploy(_))
                .then_some(File::open("/dev/null"))
                .transpose()
                .context("failed to open temporary directory")?;

            let profile = File::create(profile).context("failed to create profile file")?;
            let exec_profile = profile
                .try_clone()
                .context("failed to duplicate profile file handle")?;
            let flame_layer = tracing_flame::FlameLayer::new(profile);
            let guard = flame_layer.flush_on_drop();
            (Some(flame_layer), Some(guard), Some(exec_profile))
        } else {
            (None, None, None)
        };

        let registry = tracing_subscriber::registry().with(fmt_layer);
        #[cfg(feature = "bench")]
        let registry = registry.with(flame_layer);
        registry.init();

        info!("logging initialized!");
        info!("CLI opts: {:?}", self);

        match self.cmd {
            Subcommands::Run(cmd) => cmd.execute(
                #[cfg(unix)]
                log_level,
                #[cfg(all(unix, feature = "bench"))]
                profile,
            ),
            Subcommands::Config(cmd) => cmd.dispatch(),
            Subcommands::Deploy(cmd) => cmd.execute(
                #[cfg(unix)]
                log_level,
                #[cfg(all(unix, feature = "bench"))]
                profile,
            ),
            #[cfg(enarx_with_shim)]
            Subcommands::Key(cmd) => cmd.dispatch(),
            Subcommands::Platform(cmd) => cmd.dispatch(),
            Subcommands::Package(cmd) => cmd.dispatch(),
            Subcommands::Repo(cmd) => cmd.dispatch(),
            #[cfg(enarx_with_shim)]
            Subcommands::Sign(cmd) => cmd.execute(),
            Subcommands::Tree(cmd) => cmd.dispatch(),
            Subcommands::User(cmd) => cmd.dispatch(),
            Subcommands::Unstable(cmd) => cmd.dispatch(),
            #[cfg(enarx_with_shim)]
            Subcommands::UpdateCache => {
                match Vendor::get()? {
                    Vendor::Amd => {
                        use crate::cli::platform::snp::crl::CrlCache;
                        let crl_cache_cmd = CrlCache::default();
                        crl_cache_cmd.execute()?;
                    }
                    Vendor::Intel => {
                        use crate::cli::platform::sgx::crl::CrlCache;
                        use crate::cli::platform::sgx::tcb::TcbCache;
                        let crl_cache_cmd = CrlCache::default();
                        crl_cache_cmd.execute()?;
                        let tcb_cache_cmd = TcbCache::default();
                        tcb_cache_cmd.execute()?;
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
            #[cfg(enarx_with_shim)]
            Subcommands::Initialize => {
                match Vendor::get()? {
                    Vendor::Amd => {
                        use crate::cli::platform::snp::update::Options;
                        let opt = Options::default();
                        opt.execute()?;
                    }
                    Vendor::Intel => {
                        use crate::cli::platform::sgx::register::Options;
                        let opt = Options::default();
                        opt.execute()?;
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

/// `enarx` subcommands and their options/arguments.
#[derive(Subcommand, Debug)]
enum Subcommands {
    Run(run::Options),
    Deploy(deploy::Options),
    #[clap(subcommand)]
    Config(config::Subcommands),
    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Key(key::Subcommands),
    #[clap(subcommand)]
    Platform(platform::Subcommands),
    #[clap(subcommand)]
    Package(package::Subcommands),
    #[clap(subcommand)]
    Repo(repo::Subcommands),
    #[cfg(enarx_with_shim)]
    #[clap(hide = true)]
    Sign(sign::Options),
    #[clap(subcommand, hide = true)]
    Tree(tree::Subcommands),
    #[clap(subcommand)]
    User(user::Subcommands),
    #[clap(subcommand, hide = true)]
    Unstable(unstable::Subcommands),
    #[cfg(enarx_with_shim)]
    /// Metacommand to update platform-specific caches, if a platform is detected.
    UpdateCache,
    #[cfg(enarx_with_shim)]
    /// Metacommand to perform first-time platform-specific initialization, if a platform is detected.
    Initialize,
}

/// Common backend and shim options
#[derive(Args, Debug)]
pub struct BackendOptions {
    /// Set which backend to use
    #[clap(long, env = "ENARX_BACKEND")]
    backend: Option<String>,
    // TODO: Path to an external shim binary?
    //shim: Option<PathBuf>,
}

impl BackendOptions {
    pub fn pick(&self) -> anyhow::Result<&dyn Backend> {
        if let Some(ref name) = self.backend {
            match BACKENDS.deref().iter().find(|b| b.name() == name) {
                None => {
                    bail!("Keep backend identifier {:?} is unknown.", name)
                }
                Some(backend) => {
                    if !backend.have() {
                        bail!("Keep backend {:?} is not available on this platform.", name)
                    }
                    if !backend.configured() {
                        bail!("Keep backend {:?} is available on this platform, but the machine is misconfigured. Please check with `enarx platform info`.", name)
                    }
                    Ok(backend)
                }
            }
        } else {
            BACKENDS.deref().iter().find(|b| b.have()).ok_or_else(|| {
                anyhow!(
                    "No supported backend found. Please check your machine with `$ enarx platform info`."
                )
            })
        }
        .map(|b| &**b)
    }
}

/// Common logging / output options
#[derive(Args, Debug)]
pub struct LogOptions {
    /// Set fancier logging filters.
    ///
    /// This is equivalent to the `RUST_LOG` environment variable.
    /// For more info, see the [EnvFilter] documentation.
    #[clap(long = "log-filter", env = "ENARX_LOG")]
    log_filter: Option<String>,

    /// Set log output target ("stderr", "stdout")
    #[clap(long, default_value = "stderr")]
    log_target: LogTarget,

    /// If set, a performance profile will be written to this location.
    #[cfg(feature = "bench")]
    #[clap(long)]
    profile: Option<camino::Utf8PathBuf>,
}

/// Represents logging target.
#[derive(Debug, Clone, Copy)]
enum LogTarget {
    Stdout,
    Stderr,
}

/// Convert a str to a LogTarget. This is how Clap parses CLI args.
impl FromStr for LogTarget {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => Err(anyhow!("unknown log target {:?}", s)),
        }
    }
}
