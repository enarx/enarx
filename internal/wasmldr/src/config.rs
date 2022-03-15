// SPDX-License-Identifier: Apache-2.0
//! The Enarx Configuration file format

use std::{collections::HashMap, ops::Deref};

use serde::{de::Error as _, Deserialize, Deserializer};
use url::Url;

fn default_port() -> u16 {
    443
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name(String);

impl From<String> for Name {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Name {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;

        if name.contains(':') {
            return Err(D::Error::custom("invalid name"));
        }

        Ok(Self(name))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub env: HashMap<String, String>,

    #[serde(default)]
    pub args: Vec<String>,

    #[serde(default)]
    pub files: Vec<File>,

    #[serde(default)]
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
            steward: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind")]
pub enum File {
    #[serde(rename = "null")]
    Null { name: Option<Name> },

    #[serde(rename = "stdin")]
    Stdin { name: Option<Name> },

    #[serde(rename = "stdout")]
    Stdout { name: Option<Name> },

    #[serde(rename = "stderr")]
    Stderr { name: Option<Name> },

    #[serde(rename = "listen")]
    Listen {
        name: Name,

        #[serde(default = "default_port")]
        port: u16,

        #[serde(default)]
        prot: Protocol,
    },

    #[serde(rename = "connect")]
    Connect {
        name: Option<Name>,

        #[serde(default = "default_port")]
        port: u16,

        #[serde(default)]
        prot: Protocol,

        host: String,
    },
}

impl File {
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
pub enum Protocol {
    #[serde(rename = "tls")]
    Tls,

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
        host = "google.com"
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
                    prot: Protocol::Tcp
                },
                File::Stdout { name: None },
                File::Null { name: None },
                File::Stderr { name: None },
                File::Connect {
                    name: None,
                    port: 443,
                    prot: Protocol::Tls,
                    host: "google.com".into(),
                },
            ]
        );
    }

    #[test]
    fn names() {
        let cfg: Config = toml::from_str(CONFIG).unwrap();

        assert_eq!(
            vec!["stdin", "X", "stdout", "null", "stderr", "google.com"],
            cfg.files.iter().map(|f| f.name()).collect::<Vec<_>>()
        );
    }
}
