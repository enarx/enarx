// SPDX-License-Identifier: Apache-2.0

//! enarx-exec-wasmtime to be used by enarx-exec-wasmtime-bin or the enarx frontend

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]

mod runtime;
mod workload;

pub use workload::{Package, Workload, PACKAGE_CONFIG, PACKAGE_ENTRYPOINT};

use runtime::Runtime;

/// The Arguments
// NOTE: `repr(C)` is required, otherwise `toml` serialization fails with `values must be emitted before tables`
#[derive(Debug)]
#[cfg_attr(unix, derive(serde::Deserialize, serde::Serialize))]
#[repr(C)]
pub struct Args {
    /// Package
    pub package: Package,
}

/// Execute
pub fn execute_with_args(args: Args) -> anyhow::Result<()> {
    Runtime::execute(args.package).map(|_| ())
}

/// Execute
///
/// with configuration read from file descriptor 3.
#[cfg(unix)]
pub fn execute() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Read;
    use std::mem::forget;
    use std::os::unix::io::FromRawFd;
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
    use super::*;

    use std::io::{Seek, Write};
    #[cfg(unix)]
    use std::os::unix::io::IntoRawFd;

    use anyhow::Context;
    use tempfile::tempfile;
    use wasmtime::Val;

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

    pub fn run(wasm: &[u8]) -> anyhow::Result<Vec<Val>> {
        let mut file = tempfile().context("failed to create module file")?;
        file.write(wasm).context("failed to write module to file")?;
        file.rewind().context("failed to rewind file")?;
        #[cfg(unix)]
        let file = file.into_raw_fd();
        Runtime::execute(Package::Local {
            wasm: file,
            conf: None,
        })
    }

    #[test]
    fn workload_run_return_1() {
        let bytes = wat::parse_str(RETURN_1_WAT).expect("error parsing wat");

        let results: Vec<i32> = run(&bytes)
            .unwrap()
            .iter()
            .map(wasmtime::Val::unwrap_i32)
            .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let bytes = wat::parse_str(NO_EXPORT_WAT).expect("error parsing wat");

        match run(&bytes) {
            Err(..) => (),
            _ => panic!("unexpected success"),
        }
    }

    #[test]
    fn workload_run_hello_wasi() {
        let bytes = wat::parse_str(HELLO_WASI_WAT).expect("error parsing wat");
        let values = run(&bytes).unwrap();
        assert_eq!(values.len(), 0);

        // TODO/FIXME: we need a way to configure WASI stdout so we can capture
        // and check it here...
    }
}
