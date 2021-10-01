// SPDX-License-Identifier: Apache-2.0

use log::{debug, warn};
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

    // TODO: plaintext stdio to/from the (untrusted!) host system isn't a
    // secure default behavior. But.. we don't have any *trusted* I/O yet, so..
    warn!("🌭DEV-ONLY BUILD🌭: inheriting stdio from calling process");
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

    #[test]
    fn workload_run_return_1() {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/fixtures/return_1.wasm")).to_vec();

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
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/fixtures/no_export.wasm")).to_vec();

        match workload::run(&bytes, empty::<String>(), empty::<(String, String)>()) {
            Err(workload::Error::ExportNotFound) => {}
            _ => panic!("unexpected error"),
        };
    }

    #[test]
    fn workload_run_wasi_snapshot1() {
        let bytes =
            include_bytes!(concat!(env!("OUT_DIR"), "/fixtures/wasi_snapshot1.wasm")).to_vec();

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

    #[cfg(bundle_tests)]
    #[test]
    fn workload_run_bundled() {
        let bytes = include_bytes!(concat!(
            env!("OUT_DIR"),
            "/fixtures/hello_wasi_snapshot1.bundled.wasm"
        ))
        .to_vec();

        workload::run(&bytes, empty::<&str>(), empty::<(&str, &str)>()).unwrap();

        let output = std::fs::read("stdout.txt").unwrap();
        assert_eq!(output, "Hello, world!\n".to_string().into_bytes());
    }
}
