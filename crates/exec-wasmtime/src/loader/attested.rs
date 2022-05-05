// SPDX-License-Identifier: Apache-2.0

use super::{Acquired, Attested, Loader};
use crate::Package;

use std::io::Read;
use std::os::unix::prelude::FromRawFd;

use anyhow::{bail, ensure, Context, Result};
use ureq::Response;

/// Maximum size of WASM module in bytes
const MAX_WASM_SIZE: u64 = 10_000_000;

const DRAWBRIDGE_DIRECTORY_MEDIA_TYPE: &str = "application/vnd.drawbridge.directory.v1+json";
const TOML_MEDIA_TYPE: &str = "application/toml";
const WASM_MEDIA_TYPE: &str = "application/wasm";

fn get(url: impl AsRef<str>) -> Result<Response> {
    let url = url.as_ref();
    ureq::get(url)
        .call()
        .with_context(|| format!("failed to GET `{}`", url))
}

fn response_into_wasm(res: Response) -> Result<Vec<u8>> {
    // TODO: Initialize with capacity of Content-Length if set.
    let mut wasm = Vec::new();
    res.into_reader()
        .take(MAX_WASM_SIZE)
        .read_to_end(&mut wasm)
        .context("failed to read WASM module contents")?;
    // TODO: Verify Content-Digest
    Ok(wasm)
}

fn get_drawbridge_directory(url: impl AsRef<str>) -> Result<(Vec<u8>, String)> {
    let url = url.as_ref().trim_end_matches('/');
    // TODO: refactor into `get_typed<WASM_MEDIA_TYPE>` once `&str` is supported as
    // const generic argument
    let wasm = get(format!("{}/{}", url, "main.wasm"))
        .and_then(|res| {
            let typ = res.content_type();
            ensure!(
                typ == WASM_MEDIA_TYPE,
                format!(
                    "expected `main.wasm` to have `{}` media type, got `{}`",
                    WASM_MEDIA_TYPE, typ
                )
            );
            Ok(res)
        })
        .and_then(response_into_wasm)?;

    // TODO: refactor into `get_typed<TOML_MEDIA_TYPE>` once `&str` is supported as
    // const generic argument
    let conf = get(format!("{}/{}", url, "Enarx.toml"))
        .and_then(|res| {
            let typ = res.content_type();
            ensure!(
                typ == TOML_MEDIA_TYPE,
                format!(
                    "expected `Enarx.toml` to have `{}` media type, got `{}`",
                    TOML_MEDIA_TYPE, typ
                )
            );
            Ok(res)
        })?
        // TODO: Verify Content-Digest
        .into_string()?;

    Ok((wasm, conf))
}

impl Loader<Attested> {
    pub fn next(self) -> Result<Loader<Acquired>> {
        let (webasm, config) = match self.0.package {
            Package::Remote(ref url) => {
                let res = get(url.as_str())?;
                match res.content_type() {
                    WASM_MEDIA_TYPE => response_into_wasm(res).map(|webasm| (webasm, None))?,
                    DRAWBRIDGE_DIRECTORY_MEDIA_TYPE => get_drawbridge_directory(url.as_str())
                        .map(|(webasm, config)| (webasm, Some(config)))?,
                    t => bail!("unsupported content type: {}", t),
                }
            }
            Package::Local { wasm, conf } => {
                let mut webasm = Vec::new();
                unsafe { std::fs::File::from_raw_fd(wasm) }
                    .read_to_end(&mut webasm)
                    .context("failed to read WASM module")?;

                let config = if let Some(conf) = conf {
                    let mut config = String::new();
                    unsafe { std::fs::File::from_raw_fd(conf) }
                        .read_to_string(&mut config)
                        .context("failed to read config")?;
                    Some(config)
                } else {
                    None
                };
                (webasm, config)
            }
        };
        let config = if let Some(ref config) = config {
            toml::from_str(config).context("failed to parse config")?
        } else {
            Default::default()
        };
        Ok(Loader(Acquired {
            srvcfg: self.0.srvcfg,
            cltcfg: self.0.cltcfg,
            config,
            webasm,
        }))
    }
}
