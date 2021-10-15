// SPDX-License-Identifier: Apache-2.0

use log::{debug, info};
use nbytes::bytes;
use wasmtime_wasi::sync::WasiCtxBuilder;

/// The error codes of workload execution.
// clippy doesn't like how "ConfigurationError" ends with "Error", so..
#[allow(clippy::enum_variant_names)]
// TODO: use clippy-approved names when we rework these and refactor run();
//       until then
#[derive(Debug)]
pub enum Error {
    /// configuration error
    ConfigurationError,
    /// export not found
    ExportNotFound,
    /// module instantiation failed
    InstantiationFailed,
    /// call failed
    CallFailed,
    /// I/O error
    IoError(std::io::Error),
    /// WASI error
    WASIError(wasmtime_wasi::Error),
    /// Arguments or environment too large
    StringTableError,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<wasmtime_wasi::Error> for Error {
    fn from(err: wasmtime_wasi::Error) -> Self {
        Self::WASIError(err)
    }
}

// We use this to provide an exitcode for std::process::exit.
impl From<Error> for i32 {
    fn from(err: Error) -> Self {
        use Error::*;
        // For now, the exit codes we're using here are pulled from FreeBSD's
        // sysexits.h. This is really just to help us (the Enarx developers)
        // debug failures while we're getting things working. The values may
        // change without warning - this is not part of the public API.
        match err {
            // wasmtime/WASI/module setup errors -> EX_DATAERR
            ConfigurationError => 65,
            StringTableError => 65,
            InstantiationFailed => 65,
            ExportNotFound => 65,
            CallFailed => 65,

            // Internal WASI errors -> EX_SOFTWARE
            WASIError(_) => 70,

            // General IO errors -> EX_IOERR
            IoError(_) => 74,
        }
    }
}

/// Result type used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

/// Runs a WebAssembly workload.
// TODO: refactor this into multiple steps
// Since we're not bundling the launch/deployment config into `bytes`, the
// naive solution would just be to add new arguments for those things, like
// WasmFeatures, stdio handling, etc - but that gets messy quick.
// Instead we should probably refactor this into distinct steps, each with
// its own config options (and error variants - see above).
pub fn run<T: AsRef<str>, U: AsRef<str>>(
    bytes: impl AsRef<[u8]>,
    args: impl IntoIterator<Item = T>,
    envs: impl IntoIterator<Item = (U, U)>,
) -> Result<Box<[wasmtime::Val]>> {
    debug!("configuring wasmtime engine");
    let mut config = wasmtime::Config::new();
    // Support module-linking (https://github.com/webassembly/module-linking)
    config.wasm_module_linking(true);
    // module-linking requires multi-memory
    config.wasm_multi_memory(true);

    // Prefer dynamic memory allocation style over static memory
    config.static_memory_maximum_size(0);
    config.static_memory_guard_size(0);
    config.dynamic_memory_guard_size(0);
    config.dynamic_memory_reserved_for_growth(bytes![1; MiB]);

    let engine = wasmtime::Engine::new(&config).or(Err(Error::ConfigurationError))?;

    debug!("instantiating wasmtime linker");
    let mut linker = wasmtime::Linker::new(&engine);

    // TODO: read config, set up filehandles & sockets, etc etc

    debug!("adding WASI to linker");
    wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;

    debug!("creating WASI context");
    let mut wasi = WasiCtxBuilder::new();
    for arg in args {
        wasi = wasi.arg(arg.as_ref()).or(Err(Error::StringTableError))?;
    }
    for kv in envs {
        wasi = wasi
            .env(kv.0.as_ref(), kv.1.as_ref())
            .or(Err(Error::StringTableError))?;
    }

    // v0.1.0 KEEP-CONFIG HACK: let wasmtime/wasi inherit our stdio.
    // FIXME: this isn't a safe default if you don't trust the host!
    info!("inheriting stdio from calling process");
    wasi = wasi.inherit_stdio();

    debug!("creating wasmtime Store");
    let mut store = wasmtime::Store::new(&engine, wasi.build());

    debug!("instantiating module from bytes");
    let module = wasmtime::Module::from_binary(&engine, bytes.as_ref())?;

    debug!("adding module to store");
    linker
        .module(&mut store, "", &module)
        .or(Err(Error::InstantiationFailed))?;

    // TODO: use the --invoke FUNCTION name, if any
    debug!("getting module's default function");
    let func = linker
        .get_default(&mut store, "")
        .or(Err(Error::ExportNotFound))?;

    debug!("calling function");
    func.call(store, Default::default())
        .or(Err(Error::CallFailed))
}

#[cfg(test)]
pub(crate) mod test {
    use crate::workload;
    use std::iter::empty;

    const NO_EXPORT_WAT: &'static str = r#"(module
      (memory (export "") 1)
    )"#;

    const RETURN_1_WAT: &'static str = r#"(module
      (func (export "") (result i32) i32.const 1)
    )"#;

    const WASI_COUNT_ARGS_WAT: &'static str = r#"(module
      (import "wasi_snapshot_preview1" "args_sizes_get"
        (func $__wasi_args_sizes_get (param i32 i32) (result i32)))
      (func (export "_start") (result i32)
        (i32.store (i32.const 0) (i32.const 0))
        (i32.store (i32.const 4) (i32.const 0))
        (call $__wasi_args_sizes_get (i32.const 0) (i32.const 4))
        drop
        (i32.load (i32.const 0))
      )
      (memory 1)
      (export "memory" (memory 0))
    )"#;

    const HELLO_WASI_WAT: &'static str = r#"(module
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

        let results: Vec<i32> =
            workload::run(&bytes, empty::<String>(), empty::<(String, String)>())
                .unwrap()
                .iter()
                .map(|v| v.unwrap_i32())
                .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let bytes = wat::parse_str(NO_EXPORT_WAT).expect("error parsing wat");

        match workload::run(&bytes, empty::<String>(), empty::<(String, String)>()) {
            Err(workload::Error::ExportNotFound) => {}
            _ => panic!("unexpected error"),
        };
    }

    #[test]
    fn workload_run_wasi_count_args() {
        let bytes = wat::parse_str(WASI_COUNT_ARGS_WAT).expect("error parsing wat");

        let results: Vec<i32> = workload::run(
            &bytes,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            vec![("k", "v")],
        )
        .unwrap()
        .iter()
        .map(|v| v.unwrap_i32())
        .collect();

        assert_eq!(results, vec![3]);
    }

    #[test]
    fn workload_run_hello_wasi() {
        let bytes = wat::parse_str(HELLO_WASI_WAT).expect("error parsing wat");
        let args: Vec<String> = vec![];
        let envs: Vec<(String, String)> = vec![];

        let results = workload::run(&bytes, args, envs).unwrap();

        assert_eq!(results.len(), 0);

        // TODO/FIXME: we need a way to configure WASI stdout so we can capture
        // and check it here...
    }
}
