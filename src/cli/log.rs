// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{anyhow, Result};
use structopt::StructOpt;

/// Common logging / output options
#[derive(StructOpt, Debug)]
pub struct LogOptions {
    /// Increase log verbosity. Pass multiple times for more log output.
    ///
    /// By default we only show error messages. Passing `-v` will show warnings,
    /// `-vv` adds info, `-vvv` for debug, and `-vvvv` for trace.
    #[structopt(long = "verbose", short = "v", parse(from_occurrences))]
    verbosity: u8,

    /// Set fancier logging filters.
    ///
    /// This is equivalent to the `RUST_LOG` environment variable.
    /// For more info, see the `env_logger` crate documentation.
    #[structopt(long = "log-filter", env = "ENARX_LOG")]
    log_filter: Option<String>,

    /// Set log output target ("stderr", "stdout")
    #[structopt(long, default_value = "stderr")]
    log_target: LogTarget,
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

/// Convert a str to a LogTarget. This is how StructOpt parses CLI args.
impl FromStr for LogTarget {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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

impl LogOptions {
    /// Build & initialize a global logger using env_logger::Builder.
    /// As with Builder::init(), this will panic if called more than once,
    /// or if another library has already initialized a global logger.
    pub fn init_logger(&self) {
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
