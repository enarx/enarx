// SPDX-License-Identifier: Apache-2.0

//! enarx-exec-wasmtime to be used by enarx-exec-wasmtime-bin or the enarx frontend

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]

#[cfg(unix)]
mod log;
mod runtime;
mod workload;

#[cfg(unix)]
pub use log::Level as LogLevel;
pub use workload::{Package, Workload, PACKAGE_CONFIG, PACKAGE_ENTRYPOINT};

use runtime::Runtime;

use wiggle::tracing::instrument;

/// The Arguments
// NOTE: `repr(C)` is required, otherwise `toml` serialization fails with `values must be emitted before tables`
#[derive(Debug)]
#[cfg_attr(unix, derive(serde::Deserialize, serde::Serialize))]
#[repr(C)]
pub struct Args {
    /// Log level
    #[cfg(unix)]
    pub log_level: Option<log::Level>,

    /// Profile
    #[cfg(all(unix, feature = "bench"))]
    pub profile: Option<std::os::unix::prelude::RawFd>,

    /// Package
    pub package: Package,
}

/// Execute package
#[instrument]
pub fn execute_package(pkg: Package) -> anyhow::Result<()> {
    Runtime::execute(pkg).map(|_| ())
}

/// Execute with arguments read from file descriptor 3.
#[cfg(unix)]
pub fn execute() -> anyhow::Result<()> {
    use std::io::Read;
    use std::mem::forget;
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream;

    use anyhow::Context;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry;

    // This is the FD of a Unix socket on which the host will send the TOML-encoded execution arguments
    // and shutdown the write half of it immediately after.
    // TODO: Use the write half of the socket to write logs/errors to the host
    let mut host = unsafe { UnixStream::from_raw_fd(3) };

    let mut args = String::new();
    host.read_to_string(&mut args)
        .context("failed to read arguments")?;

    // The FD is managed by the host or its parent.
    forget(host);

    let Args {
        log_level,
        #[cfg(feature = "bench")]
        profile,
        package,
    } = toml::from_str(&args).context("failed to decode arguments")?;

    #[cfg(feature = "bench")]
    let (flame_layer, _guard) = if let Some(profile) = profile {
        use std::fs::File;
        let profile = unsafe { File::from_raw_fd(profile) };
        let flame_layer = tracing_flame::FlameLayer::new(profile);
        let guard = flame_layer.flush_on_drop();
        (Some(flame_layer), Some(guard))
    } else {
        (None, None)
    };
    let log_level: LevelFilter = log_level.map(Into::into).into();
    {
        let fmt_layer = tracing_subscriber::fmt::layer()
            // TODO: Default to a secure log target
            // https://github.com/enarx/enarx/issues/1042
            .with_writer(std::io::stderr)
            .with_filter(log_level);
        let registry = registry().with(fmt_layer);
        #[cfg(feature = "bench")]
        let registry = registry.with(flame_layer);
        let _guard = registry.set_default();
        execute_package(package)?;
    }
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
