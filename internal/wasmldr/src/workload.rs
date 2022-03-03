// SPDX-License-Identifier: Apache-2.0

use crate::config;

use log::debug;
use wasmtime_wasi::sync::{TcpListener, WasiCtxBuilder};

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

impl From<wasi_common::StringArrayError> for Error {
    fn from(_err: wasi_common::StringArrayError) -> Self {
        Self::StringTableError
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
pub fn run(bytes: impl AsRef<[u8]>, ldr_config: &config::Config) -> Result<Vec<wasmtime::Val>> {
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
    config.dynamic_memory_reserved_for_growth(16 * 1024 * 1024);

    let engine = wasmtime::Engine::new(&config).or(Err(Error::ConfigurationError))?;

    debug!("instantiating wasmtime linker");
    let mut linker = wasmtime::Linker::new(&engine);

    // TODO: read config, set up filehandles & sockets, etc etc

    debug!("adding WASI to linker");
    wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;

    debug!("creating WASI context");
    let mut wasi = WasiCtxBuilder::new();

    debug!("Processing loader config {:#?}", &ldr_config);

    if let Some(ref files) = ldr_config.files {
        for file in files {
            match (file.type_.as_ref(), file.name.as_ref()) {
                ("stdio", "stdin") => wasi = wasi.inherit_stdin(),
                ("stdio", "stdout") => wasi = wasi.inherit_stdout(),
                ("stdio", "stderr") => wasi = wasi.inherit_stderr(),
                _ => {}
            }
        }
    }

    let mut num_fd = 3;
    let mut fd_names: Vec<String> = Vec::new();

    if let Some(ref files) = ldr_config.files {
        for file in files {
            match file.type_.as_ref() {
                "tcp_listen" => {
                    let port = file
                        .port
                        .expect("Config file `tcp_listen` has no `port` field set");
                    let addr = file.addr.clone().unwrap_or_else(|| ":::".to_string());
                    let stdlistener = std::net::TcpListener::bind((addr.as_str(), port))
                        .unwrap_or_else(|e| panic!("Could not bind to {addr}:{port}: {e}"));
                    stdlistener
                        .set_nonblocking(true)
                        .expect("Could not set nonblocking on TcpListener");

                    wasi = wasi.preopened_socket(num_fd, TcpListener::from_std(stdlistener))?;
                    num_fd += 1;
                    wasi = wasi.env("LISTEN_FDS", &(num_fd - 3).to_string())?;
                    fd_names.push(file.name.clone())
                }
                "stdio" => {}
                field => {
                    panic!("Unknown field '{field}' in config file");
                }
            }
        }
        if !fd_names.is_empty() {
            wasi = wasi.env("LISTEN_FDNAMES", &fd_names.join(":"))?;
        }
    }

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
    let mut results = vec![wasmtime::Val::null(); func.ty(&store).results().len()];

    func.call(store, Default::default(), &mut results)
        .or(Err(Error::CallFailed))?;

    Ok(results)
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{config, workload};

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

        let results: Vec<i32> = workload::run(&bytes, &config::Config::default())
            .unwrap()
            .iter()
            .map(wasmtime::Val::unwrap_i32)
            .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let bytes = wat::parse_str(NO_EXPORT_WAT).expect("error parsing wat");

        match workload::run(&bytes, &config::Config::default()) {
            Err(workload::Error::ExportNotFound) => {}
            _ => panic!("unexpected error"),
        };
    }

    #[test]
    fn workload_run_hello_wasi() {
        let bytes = wat::parse_str(HELLO_WASI_WAT).expect("error parsing wat");
        let results = workload::run(&bytes, &config::Config::default()).unwrap();

        assert_eq!(results.len(), 0);

        // TODO/FIXME: we need a way to configure WASI stdout so we can capture
        // and check it here...
    }
}
