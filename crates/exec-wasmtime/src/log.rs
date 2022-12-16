// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// The level at which `exec-wasmtime` should log.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Level {
    /// Trace log level
    Trace,
    /// Debug log level
    Debug,
    /// Info log level
    Info,
    /// Warn log level
    Warn,
    /// Error log level
    Error,
}

impl From<tracing::Level> for Level {
    fn from(level: tracing::Level) -> Self {
        match level {
            tracing::Level::TRACE => Self::Trace,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::INFO => Self::Info,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::ERROR => Self::Error,
        }
    }
}

impl From<Level> for tracing::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::Trace => Self::TRACE,
            Level::Debug => Self::DEBUG,
            Level::Info => Self::INFO,
            Level::Warn => Self::WARN,
            Level::Error => Self::ERROR,
        }
    }
}
