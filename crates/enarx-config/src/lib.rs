// SPDX-License-Identifier: Apache-2.0

//! Configuration for a WASI application in an Enarx Keep
//!
#![doc = include_str!("../README.md")]
#![doc = include_str!("../Enarx_toml.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]

use std::{collections::HashMap, ops::Deref};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use url::Url;

const fn default_port() -> u16 {
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

impl From<String> for FileName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for FileName {
    fn from(value: &str) -> Self {
        Self(value.into())
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

        if name.contains(':') {
            return Err(D::Error::custom("invalid value for `name` contains ':'"));
        }

        Ok(Self(name))
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
/// name = "LISTEN"
/// kind = "listen"
/// prot = "tls"
/// port = 12345
/// "#;
///
/// let config: Config = toml::from_str(CONFIG).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The environment variables to provide to the application
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,

    /// The arguments to provide to the application
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// The array of pre-opened file descriptors
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<File>,

    /// An optional Steward URL
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steward: Option<Url>,
}

impl Default for Config {
    fn default() -> Self {
        let files = vec![
            File::Stdin { name: None },
            File::Stdout { name: None },
            File::Stderr { name: None },
        ];

        Self {
            env: HashMap::new(),
            args: vec![],
            files,
            steward: None, // TODO: Default to a deployed Steward instance
        }
    }
}

/// Parameters for a pre-opened file descriptor
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum File {
    /// File descriptor of `/dev/null`
    #[serde(rename = "null")]
    Null {
        /// Name assigned to the file descriptor
        name: Option<FileName>,
    },

    /// File descriptor of stdin
    #[serde(rename = "stdin")]
    Stdin {
        /// Name assigned to the file descriptor
        name: Option<FileName>,
    },

    /// File descriptor of stdout
    #[serde(rename = "stdout")]
    Stdout {
        /// Name assigned to the file descriptor
        name: Option<FileName>,
    },

    /// File descriptor of stderr
    #[serde(rename = "stderr")]
    Stderr {
        /// Name assigned to the file descriptor
        name: Option<FileName>,
    },

    /// File descriptor of a TCP listen socket
    #[serde(rename = "listen")]
    Listen {
        /// Name assigned to the file descriptor
        name: FileName,

        /// Address to listen on
        #[serde(default = "default_addr")]
        addr: String,

        /// Port to listen on
        #[serde(default = "default_port")]
        port: u16,

        /// Protocol to use
        #[serde(default)]
        prot: Protocol,
    },

    /// File descriptor of a TCP stream socket
    #[serde(rename = "connect")]
    Connect {
        /// Name assigned to the file descriptor
        name: Option<FileName>,

        /// Host address to connect to
        host: String,

        /// Port to connect to
        #[serde(default = "default_port")]
        port: u16,

        /// Protocol to use
        #[serde(default)]
        prot: Protocol,
    },
}

impl File {
    /// Get the name for a file descriptor
    pub fn name(&self) -> &str {
        match self {
            Self::Null { name } => name.as_deref().unwrap_or("null"),
            Self::Stdin { name } => name.as_deref().unwrap_or("stdin"),
            Self::Stdout { name } => name.as_deref().unwrap_or("stdout"),
            Self::Stderr { name } => name.as_deref().unwrap_or("stderr"),
            Self::Listen { name, .. } => name,
            Self::Connect { name, host, .. } => name.as_deref().unwrap_or(host),
        }
    }
}

/// Protocol to use for a connection
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    /// Transparently wrap the TCP connection with the TLS protocol
    #[serde(rename = "tls")]
    Tls,

    /// Normal TCP connection
    #[serde(rename = "tcp")]
    Tcp,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Tls
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
    "#;

    #[test]
    fn values() {
        let cfg: Config = toml::from_str(CONFIG).unwrap();

        assert_eq!(
            cfg.files,
            vec![
                File::Stdin { name: None },
                File::Listen {
                    name: "X".into(),
                    port: 9000,
                    prot: Protocol::Tcp,
                    addr: default_addr()
                },
                File::Stdout { name: None },
                File::Null { name: None },
                File::Stderr { name: None },
                File::Connect {
                    name: None,
                    port: default_port(),
                    prot: Protocol::Tls,
                    host: "example.com".into(),
                },
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
            "invalid value for `name` contains ':' for key `files` at line 2 column 9"
        );
    }
}
