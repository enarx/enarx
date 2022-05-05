// SPDX-License-Identifier: Apache-2.0

//! enarx-exec-wasmtime to be used by enarx-exec-wasmtime-bin or the enarx frontend

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]
#![feature(core_ffi_c)]

mod config;
mod loader;

use loader::Loader;

use std::io::Read;
use std::mem::forget;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use url::Url;

/// Package to execute
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

/// The Arguments
// NOTE: Order of fields matters for this struct and `Package` seem to be required to be the last
// field, otherwise `toml` serialization fails with `values must be emitted before tables`
#[derive(Debug, Deserialize, Serialize)]
pub struct Args {
    #[serde(default)]
    /// Optional Steward URL
    pub steward: Option<Url>,

    /// Package
    pub package: Package,
}

/// Execute
pub fn execute() -> anyhow::Result<()> {
    let mut host = unsafe { UnixStream::from_raw_fd(3) };

    let mut args = String::new();
    host.read_to_string(&mut args)
        .context("failed to read arguments")?;
    let args = toml::from_str::<Args>(&args).context("failed to decode arguments")?;

    // TODO: Use the write half of the socket to write logs/errors to the host

    // Step through the state machine.
    let configured = Loader::from(args);
    let requested = configured.next()?;
    let attested = requested.next()?;
    let acquired = attested.next()?;
    let compiled = acquired.next()?;
    let connected = compiled.next()?;
    let completed = connected.next()?;
    drop(completed);

    forget(host);
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
