// SPDX-License-Identifier: Apache-2.0

//! Workload-related functionality and definitions.

use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::prelude::FromRawFd;

use anyhow::{anyhow, bail, ensure, Context, Result};
use drawbridge_client::types::{Meta, TagEntry, TreeDirectory, TreeEntry, TreeName, TreePath};
use drawbridge_client::{scope, Client, Entity, Node, Scope};
use enarx_config::Config;
use once_cell::sync::Lazy;
use ureq::serde_json;
use url::Url;
use wiggle::tracing::instrument;

/// Name of package entrypoint file
pub static PACKAGE_ENTRYPOINT: Lazy<TreeName> = Lazy::new(|| "main.wasm".parse().unwrap());

/// Name of package config file
pub static PACKAGE_CONFIG: Lazy<TreeName> = Lazy::new(|| "Enarx.toml".parse().unwrap());

/// Maximum size of WASM module in bytes
const MAX_WASM_SIZE: u64 = 100_000_000;
/// Maximum size of Enarx.toml in bytes
const MAX_CONF_SIZE: u64 = 1_000_000;
/// Maximum directory size in bytes
const MAX_DIR_SIZE: u64 = 1_000_000;

/// Maximum size of top-level response body in bytes
const MAX_TOP_SIZE: u64 = MAX_WASM_SIZE;

const TOML_MEDIA_TYPE: &str = "application/toml";
const WASM_MEDIA_TYPE: &str = "application/wasm";

/// Package to execute
#[derive(Debug)]
#[cfg_attr(unix, derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(unix, serde(deny_unknown_fields, tag = "t", content = "c"))]
pub enum Package {
    /// Remote URL to fetch package from
    Remote(Url),

    /// Local package
    #[cfg(unix)]
    Local {
        /// Open WASM module file descriptor
        wasm: std::os::unix::prelude::RawFd,
        /// Optional open config file descriptor
        conf: Option<std::os::unix::prelude::RawFd>,
        /// Extra cmdline arguments
        args: Option<Vec<String>>,
    },

    /// Local package
    #[cfg(windows)]
    Local {
        /// Open WASM module file
        wasm: File,
        /// Optional open config file
        conf: Option<File>,
        /// Extra cmdline arguments
        args: Option<Vec<String>>,
    },
}

fn get_wasm(root: Entity<'_, impl Scope, scope::Node>, entry: &TreeEntry) -> Result<Vec<u8>> {
    ensure!(
        entry.meta.mime.essence_str() == WASM_MEDIA_TYPE,
        "invalid `{}` media type `{}`",
        *PACKAGE_ENTRYPOINT,
        entry.meta.mime.essence_str()
    );
    let (meta, wasm) = Node::new(root, &PACKAGE_ENTRYPOINT.clone().into())
        .get_bytes(MAX_WASM_SIZE)
        .with_context(|| format!("failed to fetch `{}`", *PACKAGE_ENTRYPOINT))?;
    ensure!(
        meta == entry.meta,
        "`{}` metadata does not match directory entry metadata",
        *PACKAGE_ENTRYPOINT,
    );
    Ok(wasm)
}

fn get_package(root: Entity<'_, impl Scope, scope::Node>, dir: TreeDirectory) -> Result<Workload> {
    let webasm = dir
        .get(&PACKAGE_ENTRYPOINT)
        .ok_or_else(|| anyhow!("directory does not contain `{}`", *PACKAGE_ENTRYPOINT))
        .and_then(|e| get_wasm(root.clone(), e).context("failed to get Wasm"))?;

    let entry = if let Some(entry) = dir.get(&PACKAGE_CONFIG) {
        entry
    } else {
        return Ok(Workload {
            webasm,
            config: Default::default(),
        });
    };
    ensure!(
        entry.meta.mime.essence_str() == TOML_MEDIA_TYPE,
        "invalid `{}` media type `{}`",
        *PACKAGE_CONFIG,
        entry.meta.mime.essence_str()
    );
    let (meta, config) = Node::new(root, &PACKAGE_CONFIG.clone().into())
        .get_bytes(MAX_CONF_SIZE)
        .with_context(|| format!("failed to fetch `{}`", *PACKAGE_CONFIG))?;
    ensure!(
        meta == entry.meta,
        "`{}` metadata does not match directory entry metadata",
        *PACKAGE_CONFIG,
    );
    let config = toml::from_slice(&config).context("failed to parse config")?;
    Ok(Workload {
        webasm,
        config: Some(config),
    })
}

/// Acquired workload
pub struct Workload {
    /// Wasm module
    pub webasm: Vec<u8>,

    /// Enarx keep configuration
    pub config: Option<Config>,
}

impl TryFrom<Package> for Workload {
    type Error = anyhow::Error;

    #[instrument]
    fn try_from(mut pkg: Package) -> Result<Self, Self::Error> {
        match pkg {
            Package::Remote(ref url) => {
                let cl = Client::<scope::Unknown>::new_scoped(url.clone())
                    .context("failed to construct client")?;
                let top = Entity::new(&cl);
                let (Meta { size, mime, .. }, mut rdr) = top
                    .get(MAX_TOP_SIZE)
                    .with_context(|| format!("failed to fetch top-level URL `{url}`"))?;
                match mime.essence_str() {
                    WASM_MEDIA_TYPE => {
                        ensure!(
                            size <= MAX_WASM_SIZE,
                            "Wasm size of `{size}` exceeds the limit of `{MAX_WASM_SIZE}`"
                        );
                        let size = size
                            .try_into()
                            .with_context(|| format!("failed to convert `{size}` to usize"))?;
                        let mut webasm = Vec::with_capacity(size);
                        let n = rdr
                            .read_to_end(&mut webasm)
                            .context("failed to fetch workload")?;
                        ensure!(n == size, "invalid amount of Wasm bytes fetched");
                        Ok(Workload {
                            webasm,
                            config: None,
                        })
                    }
                    TreeDirectory::<()>::TYPE => serde_json::from_reader(rdr)
                        .context("failed to decode response body")
                        .and_then(|dir| {
                            get_package(top.clone().scope(), dir).context("failed to fetch package")
                        }),
                    typ => {
                        let tag = serde_json::from_reader(rdr).with_context(|| format!("failed to decode top-level entity of type `{typ}` as either Wasm module, Drawbridge directory or a tag"))?;
                        let entry: TreeEntry = match tag {
                            TagEntry::Unsigned(e) => e,
                            TagEntry::Signed(_jws) => {
                                // TODO: Support signed tags
                                // https://github.com/enarx/enarx/issues/2167
                                bail!("signed tags are not currently supported")
                            }
                        };
                        let tree = top.child("tree");
                        let root = Node::new(tree.clone(), &TreePath::ROOT);
                        match entry.meta.mime.essence_str() {
                            WASM_MEDIA_TYPE => get_wasm(tree, &entry)
                                .map(|webasm| Workload {
                                    webasm,
                                    config: None,
                                })
                                .context("failed to fetch workload"),
                            TreeDirectory::<()>::TYPE => {
                                let (meta, dir) = root
                                    .get_json::<TreeDirectory>(MAX_DIR_SIZE)
                                    .context("failed to get root directory")?;
                                ensure!(
                                    meta == entry.meta,
                                    "directory metadata does not match tag entry metadata"
                                );
                                get_package(tree, dir).context("failed to fetch package")
                            }
                            typ => bail!("unsupported root type `{typ}`"),
                        }
                    }
                }
            }
            Package::Local {
                ref mut wasm,
                ref mut conf,
                ref mut args,
            } => {
                let mut webasm = Vec::new();
                // SAFETY: This FD was passed to us by the host and we trust that we have exclusive
                // access to it.
                #[cfg(unix)]
                let mut wasm = unsafe { File::from_raw_fd(*wasm) };

                wasm.read_to_end(&mut webasm)
                    .context("failed to read WASM module")?;

                let config = if let Some(conf) = conf.as_mut() {
                    // SAFETY: This FD was passed to us by the host and we trust that we have exclusive
                    // access to it.
                    #[cfg(unix)]
                    let mut conf = unsafe { File::from_raw_fd(*conf) };

                    let mut config = vec![];
                    conf.read_to_end(&mut config)
                        .context("failed to read config")?;
                    let mut config: Config =
                        toml::from_slice(&config).context("failed to parse config")?;
                    if let Some(args) = args {
                        config.args.append(args);
                    }
                    Some(config)
                } else {
                    if let Some(args) = args {
                        Some(Config {
                            args: args.clone(),
                            ..Default::default()
                        })
                    } else {
                        None
                    }
                };
                Ok(Workload { webasm, config })
            }
        }
    }
}
