// SPDX-License-Identifier: Apache-2.0

//! Configuration for a WASI application in an Enarx Keep
//!
#![doc = include_str!("../README.md")]
#![doc = include_str!("../Enarx_toml.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]

use std::collections::HashMap;
use std::ops::Deref;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

/// Configuration file template
pub const CONFIG_TEMPLATE: &str = r#"## Configuration for a WASI application in an Enarx Keep

## Arguments
# args = [
#      "--argument1",
#      "--argument2=foo"
# ]

## Steward
# steward = "https://attest.profian.com"

## Environment variables
# [env]
# VAR1 = "var1"
# VAR2 = "var2"

## Pre-opened file descriptors
[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

## A listen socket
# [[files]]
# name = "listen"
# kind = "listen"
# prot = "tls" # or prot = "tcp"
# port = 12345

## An outgoing connected socket
# [[files]]
# name = "stream"
# kind = "connect"
# prot = "tls" # or prot = "tcp"
# host = "localhost"
# port = 23456
"#;

const fn default_tcp_port() -> u16 {
    80
}

const fn default_tls_port() -> u16 {
    443
}

fn default_addr() -> String {
    "::".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
/// Name assigned to a file descriptor
///
/// This is used to export the `FD_NAMES` environment variable,
/// which is a concatenation of all file descriptors names seperated by `:`.
///
/// See the [crate] documentation for examples.
pub struct FileName(String);

impl TryFrom<String> for FileName {
    type Error = &'static str;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.find(':').is_some() {
            Err("file name must not contain ':'")
        } else {
            Ok(Self(name))
        }
    }
}

impl TryFrom<&str> for FileName {
    type Error = <FileName as TryFrom<String>>::Error;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        String::from(name).try_into()
    }
}

impl Deref for FileName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for FileName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        name.try_into().map_err(D::Error::custom)
    }
}

/// The configuration for an Enarx WASI application
///
/// This struct can be used with any serde deserializer.
///
/// # Examples
///
/// ```
/// extern crate toml;
/// use enarx_config::Config;
/// const CONFIG: &str = r#"
/// [[files]]
/// name = "listen"
/// kind = "listen"
/// prot = "tls"
/// port = 12345
/// "#;
///
/// let config: Config = toml::from_str(CONFIG).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// An optional Steward URL
    #[serde(default)]
    pub steward: Option<Url>,

    /// The arguments to provide to the application
    #[serde(default)]
    pub args: Vec<String>,

    /// The array of pre-opened file descriptors
    #[serde(default)]
    pub files: Vec<File>,

    /// The environment variables to provide to the application
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        let files = vec![
            File::Stdin(Default::default()),
            File::Stdout(Default::default()),
            File::Stderr(Default::default()),
        ];

        Self {
            env: HashMap::new(),
            args: vec![],
            files,
            steward: None, // TODO: Default to a deployed Steward instance
        }
    }
}

/// `/dev/null` file descriptor
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NullFile {
    /// Name assigned to the file descriptor
    name: Option<FileName>,
}

/// Standard I/O file descriptor
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioFile {
    /// Name assigned to the file descriptor
    name: Option<FileName>,
}

/// File descriptor of a listen socket
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "prot", deny_unknown_fields)]
pub enum ListenFile {
    /// TLS listen socket
    #[serde(rename = "tls")]
    Tls {
        /// Name assigned to the file descriptor
        name: FileName,

        /// Address to listen on
        #[serde(default = "default_addr")]
        addr: String,

        /// Port to listen on
        #[serde(default = "default_tls_port")]
        port: u16,
    },

    /// TCP listen socket
    #[serde(rename = "tcp")]
    Tcp {
        /// Name assigned to the file descriptor
        name: FileName,

        /// Address to listen on
        #[serde(default = "default_addr")]
        addr: String,

        /// Port to listen on
        #[serde(default = "default_tcp_port")]
        port: u16,
    },
}

/// File descriptor of a stream socket
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "prot", deny_unknown_fields)]
pub enum ConnectFile {
    /// TLS stream socket
    #[serde(rename = "tls")]
    Tls {
        /// Name assigned to the file descriptor
        name: Option<FileName>,

        /// Host address to connect to
        host: String,

        /// Port to connect to
        #[serde(default = "default_tls_port")]
        port: u16,
    },

    /// TCP stream socket
    #[serde(rename = "tcp")]
    Tcp {
        /// Name assigned to the file descriptor
        name: Option<FileName>,

        /// Host address to connect to
        host: String,

        /// Port to connect to
        #[serde(default = "default_tcp_port")]
        port: u16,
    },
}

/// Parameters for a pre-opened file descriptor
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum File {
    /// File descriptor of `/dev/null`
    #[serde(rename = "null")]
    Null(NullFile),

    /// File descriptor of stdin
    #[serde(rename = "stdin")]
    Stdin(StdioFile),

    /// File descriptor of stdout
    #[serde(rename = "stdout")]
    Stdout(StdioFile),

    /// File descriptor of stderr
    #[serde(rename = "stderr")]
    Stderr(StdioFile),

    /// File descriptor of a listen socket
    #[serde(rename = "listen")]
    Listen(ListenFile),

    /// File descriptor of a stream socket
    #[serde(rename = "connect")]
    Connect(ConnectFile),
}

impl File {
    /// Get the name for a file descriptor
    pub fn name(&self) -> &str {
        match self {
            Self::Null(NullFile { name }) => name.as_deref().unwrap_or("null"),
            Self::Stdin(StdioFile { name }) => name.as_deref().unwrap_or("stdin"),
            Self::Stdout(StdioFile { name }) => name.as_deref().unwrap_or("stdout"),
            Self::Stderr(StdioFile { name }) => name.as_deref().unwrap_or("stderr"),
            Self::Listen(ListenFile::Tls { name, .. }) => name,
            Self::Listen(ListenFile::Tcp { name, .. }) => name,
            Self::Connect(ConnectFile::Tls { name, host, .. }) => name.as_deref().unwrap_or(host),
            Self::Connect(ConnectFile::Tcp { name, host, .. }) => name.as_deref().unwrap_or(host),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const CONFIG: &str = r#"
        [[files]]
        kind = "stdin"

        [[files]]
        name = "X"
        kind = "listen"
        prot = "tcp"
        port = 9000

        [[files]]
        kind = "stdout"

        [[files]]
        kind = "null"

        [[files]]
        kind = "stderr"

        [[files]]
        kind = "connect"
        host = "example.com"
        prot = "tls"
    "#;

    #[test]
    fn values() {
        let cfg: Config = toml::from_str(CONFIG).unwrap();

        assert_eq!(
            cfg.files,
            vec![
                File::Stdin(Default::default()),
                File::Listen(ListenFile::Tcp {
                    name: "X".try_into().unwrap(),
                    port: 9000,
                    addr: default_addr()
                }),
                File::Stdout(Default::default()),
                File::Null(Default::default()),
                File::Stderr(Default::default()),
                File::Connect(ConnectFile::Tls {
                    name: Default::default(),
                    port: default_tls_port(),
                    host: "example.com".into(),
                }),
            ]
        );

        let _cfg_str = toml::to_string(&cfg).unwrap();
    }

    #[test]
    fn names() {
        let cfg: Config = toml::from_str(CONFIG).unwrap();

        assert_eq!(
            vec!["stdin", "X", "stdout", "null", "stderr", "example.com"],
            cfg.files.iter().map(|f| f.name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn invalid_name() {
        const CONFIG: &str = r#"
        [[files]]
        name = "test:"
        kind = "null"
        "#;

        let err = toml::from_str::<Config>(CONFIG).unwrap_err();
        assert_eq!(err.line_col(), Some((1, 8)));
        assert_eq!(
            err.to_string(),
            "file name must not contain ':' for key `files` at line 2 column 9"
        );
    }

    #[test]
    fn check_template() {
        let cfg_str = CONFIG_TEMPLATE
            .lines()
            .map(|l| l.trim_start_matches("# "))
            .collect::<Vec<_>>()
            .join("\n");

        let cfg: Config = toml::from_str(&cfg_str).unwrap();
        let cfg_str = toml::to_string(&cfg).unwrap();
        let cfg2: Config = toml::from_str(&cfg_str).unwrap();
        assert_eq!(cfg, cfg2);
    }
}
