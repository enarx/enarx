// SPDX-License-Identifier: Apache-2.0

mod deploy;
mod package;
mod platform;
mod repo;
mod run;
mod tree;
mod unstable;
mod user;

use crate::backend::{Backend, BACKENDS};

use std::ops::Deref;
use std::str::FromStr;

use anyhow::anyhow;
use clap::{Args, Parser, Subcommand};
use log::info;

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
    pub fn execute(self) -> anyhow::Result<()> {
        self.logger.init();

        info!("logging initialized!");
        info!("CLI opts: {:?}", self);

        self.cmd.dispatch()
    }
}

/// `enarx` subcommands and their options/arguments.
#[derive(Subcommand, Debug)]
enum Subcommands {
    Run(run::Options),
    Deploy(deploy::Options),
    #[clap(subcommand)]
    Platform(platform::Subcommands),
    #[clap(subcommand)]
    Package(package::Subcommands),
    #[clap(subcommand)]
    Repo(repo::Subcommands),
    #[clap(subcommand, hide = true)]
    Tree(tree::Subcommands),
    #[clap(subcommand)]
    User(user::Subcommands),
    #[clap(subcommand, hide = true)]
    Unstable(unstable::Subcommands),
}

impl Subcommands {
    fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Run(cmd) => cmd.execute(),
            Self::Deploy(cmd) => cmd.execute(),
            Self::Platform(subcmd) => subcmd.dispatch(),
            Self::Package(subcmd) => subcmd.dispatch(),
            Self::Repo(subcmd) => subcmd.dispatch(),
            Self::Tree(subcmd) => subcmd.dispatch(),
            Self::User(subcmd) => subcmd.dispatch(),
            Self::Unstable(subcmd) => subcmd.dispatch(),
        }
    }
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
            BACKENDS
                .deref()
                .iter()
                .find(|b| b.have() && b.name() == name)
                .ok_or_else(|| anyhow!("Keep backend {:?} is unsupported.", name))
        } else {
            BACKENDS.deref().iter().find(|b| b.have()).ok_or_else(|| {
                anyhow!(
                    "No supported backend found. Please check your machine with `$ enarx info`."
                )
            })
        }
        .map(|b| &**b)
    }
}

/// Common logging / output options
#[derive(Args, Debug)]
pub struct LogOptions {
    /// Increase log verbosity. Pass multiple times for more log output.
    ///
    /// By default we only show error messages. Passing `-v` will show warnings,
    /// `-vv` adds info, `-vvv` for debug, and `-vvvv` for trace.
    #[clap(long = "verbose", short = 'v', parse(from_occurrences))]
    verbosity: u8,

    /// Set fancier logging filters.
    ///
    /// This is equivalent to the `RUST_LOG` environment variable.
    /// For more info, see the `env_logger` crate documentation.
    #[clap(long = "log-filter", env = "ENARX_LOG")]
    log_filter: Option<String>,

    /// Set log output target ("stderr", "stdout")
    #[clap(long, default_value = "stderr")]
    log_target: LogTarget,
}

impl LogOptions {
    /// Build & initialize a global logger using env_logger::Builder.
    /// As with Builder::init(), this will panic if called more than once,
    /// or if another library has already initialized a global logger.
    pub fn init(&self) {
        let mut builder = env_logger::Builder::new();
        builder
            .filter_level(self.verbosity_level())
            .parse_filters(self.log_filter.as_ref().unwrap_or(&"".to_owned()))
            .target(self.log_target.into())
            .init();
    }

    /// Convert the -vvv.. count into a log level.
    fn verbosity_level(&self) -> log::LevelFilter {
        match self.verbosity {
            0 => log::LevelFilter::Error,
            1 => log::LevelFilter::Warn,
            2 => log::LevelFilter::Info,
            3 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        }
    }
}

/// Represents targets for debug logging.
/// This will probably grow over time.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
enum LogTarget {
    Stdout,
    Stderr,
    // FUTURE: file path, syslog/journal, ...
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

/// Convert our LogTarget to env_logger's Target
impl From<LogTarget> for env_logger::Target {
    fn from(t: LogTarget) -> Self {
        match t {
            LogTarget::Stdout => Self::Stdout,
            LogTarget::Stderr => Self::Stderr,
        }
    }
}
