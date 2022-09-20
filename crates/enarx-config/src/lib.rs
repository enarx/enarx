// SPDX-License-Identifier: Apache-2.0
//! Configuration for a WASI application in an Enarx Keep
//!
#![doc = include_str!("../README.md")]
#![doc = include_str!("../Enarx_toml.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Display};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::num::NonZeroU16;
use std::str::FromStr;

use serde::ser::SerializeMap;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use url::{Host, Url};

/// Host specification
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostSpec {
    /// Host - either Ipv4 address, Ipv6 address or a domain name
    pub host: Host<String>,
    /// Optional port
    pub port: Option<NonZeroU16>,
}

impl From<Host<String>> for HostSpec {
    fn from(host: Host<String>) -> Self {
        Self { host, port: None }
    }
}

impl<'a> From<Host<&'a str>> for HostSpec {
    fn from(host: Host<&'a str>) -> Self {
        host.to_owned().into()
    }
}

impl From<(Host<String>, Option<NonZeroU16>)> for HostSpec {
    fn from((host, port): (Host<String>, Option<NonZeroU16>)) -> Self {
        Self { host, port }
    }
}

impl From<(Host<String>, NonZeroU16)> for HostSpec {
    fn from((host, port): (Host<String>, NonZeroU16)) -> Self {
        (host, Some(port)).into()
    }
}

impl<'a> From<(Host<&'a str>, NonZeroU16)> for HostSpec {
    fn from((host, port): (Host<&'a str>, NonZeroU16)) -> Self {
        (host.to_owned(), port).into()
    }
}

impl From<(Ipv4Addr, NonZeroU16)> for HostSpec {
    fn from((host, port): (Ipv4Addr, NonZeroU16)) -> Self {
        Self {
            host: Host::Ipv4(host),
            port: Some(port),
        }
    }
}

impl From<Ipv4Addr> for HostSpec {
    fn from(host: Ipv4Addr) -> Self {
        Self {
            host: Host::Ipv4(host),
            port: None,
        }
    }
}

impl From<(Ipv6Addr, NonZeroU16)> for HostSpec {
    fn from((host, port): (Ipv6Addr, NonZeroU16)) -> Self {
        Self {
            host: Host::Ipv6(host),
            port: Some(port),
        }
    }
}

impl From<Ipv6Addr> for HostSpec {
    fn from(host: Ipv6Addr) -> Self {
        Self {
            host: Host::Ipv6(host),
            port: None,
        }
    }
}

impl ToSocketAddrs for HostSpec {
    type Iter = <String as ToSocketAddrs>::Iter;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        format!("{self}").to_socket_addrs()
    }
}

/// Host specification parsing error
#[derive(Clone, Debug)]
pub enum HostSpecParseError {
    /// Invalid host
    InvalidHost(url::ParseError),
    /// Invalid port
    InvalidPort(<NonZeroU16 as FromStr>::Err),
}

impl Display for HostSpecParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost(e) => e.fmt(f),
            Self::InvalidPort(e) => e.fmt(f),
        }
    }
}

impl FromStr for HostSpec {
    type Err = HostSpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = if s.starts_with('[') {
            // Split Ipv6 host from optional port
            const INVALID_ADDR: HostSpecParseError =
                HostSpecParseError::InvalidHost(url::ParseError::InvalidIpv6Address);

            let mut it = s.split_inclusive(']');
            let host = it.next().ok_or(INVALID_ADDR)?;
            match (it.next(), it.next()) {
                (Some(port), None) => {
                    let port = port.strip_prefix(':').ok_or(INVALID_ADDR)?;
                    (host, Some(port))
                }
                (None, None) => (host, None),
                _ => return Err(INVALID_ADDR),
            }
        } else if let Some((host, port)) = s.rsplit_once(':') {
            // Split Ipv4/domain host from optional port
            (host, Some(port))
        } else {
            (s, None)
        };
        let host = Host::parse(host).map_err(Self::Err::InvalidHost)?;
        let port = port
            .map(FromStr::from_str)
            .transpose()
            .map_err(Self::Err::InvalidPort)?;
        Ok(Self { host, port })
    }
}

impl Display for HostSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.host, self.port) {
            (Host::Ipv4(host), None) => host.fmt(f),
            (Host::Ipv6(host), None) => write!(f, "[{host}]"),
            (Host::Domain(ref host), None) => host.fmt(f),

            (Host::Ipv4(host), Some(port)) => write!(f, "{host}:{port}"),
            (Host::Ipv6(host), Some(port)) => write!(f, "[{host}]:{port}"),
            (Host::Domain(host), Some(port)) => write!(f, "{host}:{port}"),
        }
    }
}

impl<'de> Deserialize<'de> for HostSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(|e| {
            de::Error::custom(format!("failed to parse `{s}` as host specification: {e}"))
        })
    }
}

impl Serialize for HostSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

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

# Standard input file
[stdin]
kind = "host" # or kind = "null"

# Standard output file
[stdout]
kind = "host" # or kind = "null"

# Standard error file
[stderr]
kind = "host" # or kind = "null"

# Use TCP for listening on port `8080` (TLS is the default)
[network.incoming.8080]
prot = "tcp"

# Use TCP for connecting to all ports on `example.com` (TLS is the default)
[network.outgoing."example.com"]
prot = "tcp"

# Use TCP for connecting to `[::1]:8080` (TLS is the default)
[network.outgoing."[::1]:8080"]
prot = "tcp"
"#;

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
/// [network.incoming.12345]
/// prot = "tls"
/// "#;
///
/// let config: Config = toml::from_str(CONFIG).unwrap();
/// ```
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// An optional Steward URL
    pub steward: Option<Url>,

    /// The arguments to provide to the application
    pub args: Vec<String>,

    /// The environment variables to provide to the application
    pub env: HashMap<String, String>,

    /// Standard input file. Null by default.
    pub stdin: StdioFile,

    /// Standard output file. Null by default.
    pub stdout: StdioFile,

    /// Standard error file. Null by default.
    pub stderr: StdioFile,

    /// Network policy.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(default)]
    pub network: Network,
}

/// Incoming network connection policy.
///
/// This API is highly experimental and will change significantly in the future.
/// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
/// feature is important for you.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingNetwork {
    /// Default incoming network connection policy.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(default)]
    pub default: Incoming,

    /// Per-port incoming network connection policy.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(
        flatten,
        deserialize_with = "IncomingNetwork::deserialize_ports",
        serialize_with = "IncomingNetwork::serialize_ports"
    )]
    pub ports: HashMap<u16, Incoming>,
}

impl IncomingNetwork {
    /// Returns the network policy associated with specified `port`.
    pub fn get(&self, port: u16) -> &Incoming {
        if let Some(policy) = self.ports.get(&port) {
            policy
        } else {
            &self.default
        }
    }

    fn serialize_ports<S>(ports: &HashMap<u16, Incoming>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(ports.len()))?;
        for (port, spec) in ports {
            map.serialize_entry(&port.to_string(), spec)?;
        }
        map.end()
    }

    fn deserialize_ports<'de, D>(deserializer: D) -> Result<HashMap<u16, Incoming>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = HashMap<u16, Incoming>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a u16 port to network listening policy")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                let mut ports = Self::Value::with_capacity(access.size_hint().unwrap_or(0));
                while let Some((port, spec)) = access.next_entry::<&'de str, Incoming>()? {
                    let port = port.parse().map_err(|e| {
                        de::Error::custom(format!("failed to parse `{port}` as port: {e}"))
                    })?;
                    ports.insert(port, spec);
                }
                Ok(ports)
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// Outgoing network connection policy.
///
/// This API is highly experimental and will change significantly in the future.
/// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
/// feature is important for you.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutgoingNetwork {
    /// Default outgoing network connection policy.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(default)]
    pub default: Outgoing,

    /// Per-host outgoing network connection policy.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(flatten, deserialize_with = "OutgoingNetwork::deserialize_hosts")]
    pub hosts: BTreeMap<HostSpec, Outgoing>,
}

impl OutgoingNetwork {
    /// Returns the network policy associated with specified `addr`.
    pub fn get(&self, addr: &HostSpec) -> &Outgoing {
        if let Some(policy) = self.hosts.get(addr) {
            policy
        } else if let Some(policy) = self.hosts.get(&addr.host.clone().into()) {
            policy
        } else {
            &self.default
        }
    }

    fn deserialize_hosts<'de, D>(deserializer: D) -> Result<BTreeMap<HostSpec, Outgoing>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = BTreeMap<HostSpec, Outgoing>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a host specification to network connection policy")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                let mut hosts = Self::Value::new();
                while let Some((host, spec)) = access.next_entry()? {
                    // Ipv6 addresses exist, for which more than one string representation exist.
                    match hosts.get(&host) {
                        None => {
                            hosts.insert(host, spec);
                        }
                        Some(stored) if spec == *stored => {}
                        _ => {
                            return Err(de::Error::custom(format!(
                                "conflicting outgoing network host specification for `{host}`"
                            )))
                        }
                    }
                }
                Ok(hosts)
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// Network policy.
///
/// This API is highly experimental and will change significantly in the future.
/// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
/// feature is important for you.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Incoming network connection policy.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(default)]
    pub incoming: IncomingNetwork,

    /// Outgoing network connection policy
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(default)]
    pub outgoing: OutgoingNetwork,
}

/// Specification of an incoming network connection.
///
/// This API is highly experimental and will change significantly in the future.
/// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
/// feature is important for you.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "prot", deny_unknown_fields)]
pub enum Incoming {
    /// TLS listen socket.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(rename = "tls")]
    #[default]
    Tls,

    /// TCP listen socket.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(rename = "tcp")]
    Tcp,
}

/// Specification of an outgoing network connection.
///
/// This API is highly experimental and will change significantly in the future.
/// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
/// feature is important for you.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "prot", deny_unknown_fields)]
pub enum Outgoing {
    /// TLS stream socket.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(rename = "tls")]
    #[default]
    Tls,

    /// TCP stream socket.
    ///
    /// This API is highly experimental and will change significantly in the future.
    /// Please track https://github.com/enarx/enarx/issues/2367 and provide feedback if this
    /// feature is important for you.
    #[serde(rename = "tcp")]
    Tcp,
}

/// Standard I/O file configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum StdioFile {
    /// Discard standard I/O.
    #[serde(rename = "null")]
    #[default]
    Null,

    /// Forward standard I/O to host.
    #[serde(rename = "host")]
    Host,
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn default() {
        let cfg: Config = toml::from_str("").expect("failed to parse config");
        assert_eq!(cfg, Default::default());
    }

    #[test]
    fn all() {
        let cfg: Config = toml::from_str(
            r#"
steward = "https://example.com"

args = [ "first", "2" ]

[env]
TEST = "test"

[stdin]
kind = "host"

[stdout]
kind = "null"

[stderr]
kind = "host"

[network.incoming.default]
prot = "tcp"

[network.incoming.0]
prot = "tls"

[network.incoming.9000]
prot = "tcp"

[network.incoming.9001]
prot = "tls"

[network.outgoing.default]
prot = "tls"

[network.outgoing."tls.example.com"]
prot = "tls"

[network.outgoing."tls.example.com:8080"]
prot = "tcp"

[network.outgoing."tcp.example.com"]
prot = "tcp"

[network.outgoing."1.2.3.4:8080"]
prot = "tls"

[network.outgoing."1.2.3.4"]
prot = "tcp"

[network.outgoing."[2001:db8::1:0:0:1]"]
prot = "tcp"

[network.outgoing."[2001:db8::1:0:0:1]:5000"]
prot = "tls"

[network.outgoing."[::]"]
prot = "tcp"

[network.outgoing."[::1]"]
prot = "tcp"
"#,
        )
        .expect("failed to parse config");

        const IPV4: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

        const IPV6: Ipv6Addr = Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0001, 0x0000, 0x0000, 0x0001,
        );

        fn connect_port(v: u16) -> NonZeroU16 {
            NonZeroU16::new(v).unwrap()
        }

        assert_eq!(
            cfg,
            Config {
                steward: Some("https://example.com".parse().unwrap()),
                args: vec!["first".into(), "2".into()],
                env: vec![("TEST".into(), "test".into())].into_iter().collect(),
                stdin: StdioFile::Host,
                stdout: StdioFile::Null,
                stderr: StdioFile::Host,
                network: Network {
                    incoming: IncomingNetwork {
                        ports: HashMap::from([
                            (0, Incoming::Tls),
                            (9000, Incoming::Tcp),
                            (9001, Incoming::Tls)
                        ]),
                        default: Incoming::Tcp,
                    },
                    outgoing: OutgoingNetwork {
                        hosts: BTreeMap::from([
                            (Host::Domain("tls.example.com").into(), Outgoing::Tls),
                            (
                                (Host::Domain("tls.example.com"), connect_port(8080)).into(),
                                Outgoing::Tcp
                            ),
                            (Host::Domain("tcp.example.com").into(), Outgoing::Tcp),
                            ((IPV4, connect_port(8080)).into(), Outgoing::Tls),
                            (IPV4.into(), Outgoing::Tcp),
                            (IPV6.into(), Outgoing::Tcp),
                            ((IPV6, connect_port(5000)).into(), Outgoing::Tls),
                            (Ipv6Addr::UNSPECIFIED.into(), Outgoing::Tcp),
                            (Ipv6Addr::LOCALHOST.into(), Outgoing::Tcp),
                        ]),
                        ..Default::default()
                    },
                },
            }
        );
    }

    #[test]
    fn duplicate_host_equal() {
        let cfg: Config = toml::from_str(
            r#"
[network.outgoing."[::]"]
prot = "tcp"

[network.outgoing."[0:0:0:0:0:0:0:0]"]
prot = "tcp"

[network.outgoing."[0::0:0:0:0]"]
prot = "tcp"
"#,
        )
        .expect("failed to parse config");

        assert_eq!(
            cfg,
            Config {
                network: Network {
                    outgoing: OutgoingNetwork {
                        hosts: BTreeMap::from([(Ipv6Addr::UNSPECIFIED.into(), Outgoing::Tcp),]),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            }
        );
    }

    #[test]
    fn duplicate_host_unequal() {
        toml::from_str::<Config>(
            r#"
[network.outgoing."[::]"]
prot = "tcp"

[network.outgoing."[0:0:0:0:0:0:0:0]"]
prot = "tls"
"#,
        )
        .expect_err("config parsing should have failed due to conflicting host specifications");
    }

    #[test]
    fn template() {
        let cfg: Config = toml::from_str(CONFIG_TEMPLATE).expect("failed to parse config template");
        let buf = toml::to_string(&cfg).expect("failed to reencode config template");
        assert_eq!(
            toml::from_str::<Config>(&buf).expect("failed to parse reencoded config template"),
            cfg
        );
    }
}
