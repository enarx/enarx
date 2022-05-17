// SPDX-License-Identifier: Apache-2.0

//! enarx-exec-wasmtime to be used by enarx-exec-wasmtime-bin or the enarx frontend

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]
#![feature(core_ffi_c)]

mod config;
mod loader;

use loader::Loader;
use url::Url;

#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};

#[cfg(unix)]
use serde::{Deserialize, Serialize};

/// Name of package entrypoint file
pub const PACKAGE_ENTRYPOINT: &str = "main.wasm";

/// Name of package config file
pub const PACKAGE_CONFIG: &str = "Enarx.toml";

/// Package to execute
#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "t", content = "c")]
pub enum Package {
    /// Remote URL to fetch package from
    Remote(Url),

    /// Local package
    Local {
        /// Open WASM module file descriptor
        wasm: RawFd,
        /// Optional open config file descriptor
        conf: Option<RawFd>,
    },
}

/// Package to execute
#[cfg(windows)]
#[derive(Debug)]
pub enum Package {
    /// Remote URL to fetch package from
    Remote(Url),

    /// Local package
    Local {
        /// Open WASM module file
        wasm: std::fs::File,
        /// Optional open config file
        conf: Option<std::fs::File>,
    },
}

/// The Arguments
// NOTE: `repr(C)` is required, otherwise `toml` serialization fails with `values must be emitted before tables`
#[derive(Debug)]
#[cfg_attr(unix, derive(Deserialize, Serialize))]
#[repr(C)]
pub struct Args {
    /// Package
    pub package: Package,
}

/// Execute
pub fn execute_with_args(args: Args) -> anyhow::Result<()> {
    // Step through the state machine.
    let configured = Loader::from(args);
    let requested = configured.next()?;
    let attested = requested.next()?;
    let compiled = attested.next()?;
    let connected = compiled.next()?;
    let completed = connected.next()?;
    drop(completed);
    Ok(())
}

#[cfg(unix)]
/// Execute
///
/// with configuration read from file descriptor 3.
pub fn execute() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Read;
    use std::mem::forget;
    use std::os::unix::net::UnixStream;

    // This is the FD of a Unix socket on which the host will send the TOML-encoded execution arguments
    // and shutdown the write half of it immediately after.
    // TODO: Use the write half of the socket to write logs/errors to the host
    let mut host = unsafe { UnixStream::from_raw_fd(3) };

    let mut args = String::new();
    host.read_to_string(&mut args)
        .context("failed to read arguments")?;

    // The FD is managed by the host or its parent.
    forget(host);

    let args = toml::from_str::<Args>(&args).context("failed to decode arguments")?;

    execute_with_args(args)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::loader::Loader;

    const NO_EXPORT_WAT: &str = r#"(module
      (memory (export "") 1)
    )"#;

    const RETURN_1_WAT: &str = r#"(module
      (func (export "") (result i32) i32.const 1)
    )"#;

    const HELLO_WASI_WAT: &str = r#"(module
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $__wasi_proc_exit (param i32)))
      (import "wasi_snapshot_preview1" "fd_write"
        (func $__wasi_fd_write (param i32 i32 i32 i32) (result i32)))
      (func $_start
        (i32.store (i32.const 24) (i32.const 14))
        (i32.store (i32.const 20) (i32.const 0))
        (block
          (br_if 0
            (call $__wasi_fd_write
              (i32.const 1)
              (i32.const 20)
              (i32.const 1)
              (i32.const 16)))
          (br_if 0 (i32.ne (i32.load (i32.const 16)) (i32.const 14)))
          (br 1)
        )
        (call $__wasi_proc_exit (i32.const 1))
      )
      (memory 1)
      (export "memory" (memory 0))
      (export "_start" (func $_start))
      (data (i32.const 0) "Hello, world!\0a")
    )"#;

    #[test]
    fn workload_run_return_1() {
        let bytes = wat::parse_str(RETURN_1_WAT).expect("error parsing wat");

        let results: Vec<i32> = Loader::run(&bytes)
            .unwrap()
            .iter()
            .map(wasmtime::Val::unwrap_i32)
            .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let bytes = wat::parse_str(NO_EXPORT_WAT).expect("error parsing wat");

        match Loader::run(&bytes) {
            Err(..) => (),
            _ => panic!("unexpected success"),
        }
    }

    #[test]
    fn workload_run_hello_wasi() {
        let bytes = wat::parse_str(HELLO_WASI_WAT).expect("error parsing wat");
        let values = Loader::run(&bytes).unwrap();
        assert_eq!(values.len(), 0);

        // TODO/FIXME: we need a way to configure WASI stdout so we can capture
        // and check it here...
    }
}
