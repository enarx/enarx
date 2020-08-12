// SPDX-License-Identifier: Apache-2.0

/// The error codes of workload execution.
#[derive(Debug)]
pub enum Error {
    /// export not found
    ExportNotFound,
    /// module instantiation failed
    InstantiationFailed,
    /// call failed
    CallFailed,
    /// I/O error
    IoError(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

/// Result type used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

/// Runs a WebAssembly workload.
pub fn run<T: AsRef<[u8]>, U: AsRef<[u8]>, V: std::borrow::Borrow<(U, U)>>(
    bytes: impl AsRef<[u8]>,
    args: impl IntoIterator<Item = T>,
    envs: impl IntoIterator<Item = V>,
) -> Result<Box<[wasmtime::Val]>> {
    let mut config = wasmtime::Config::new();
    // Prefer dynamic memory allocation style over static memory
    config.static_memory_maximum_size(0);
    let engine = wasmtime::Engine::new(&config);
    let store = wasmtime::Store::new(&engine);
    let mut linker = wasmtime::Linker::new(&store);

    // Instantiate WASI.
    let mut builder = wasi_common::WasiCtxBuilder::new();
    builder.args(args).envs(envs);
    let ctx = builder.build().or(Err(Error::InstantiationFailed))?;
    let wasi = wasmtime_wasi::Wasi::new(linker.store(), ctx);
    wasi.add_to_linker(&mut linker)
        .or(Err(Error::InstantiationFailed))?;

    // Instantiate the command module.
    let module = wasmtime::Module::from_binary(&linker.store().engine(), bytes.as_ref())
        .or(Err(Error::InstantiationFailed))?;
    linker
        .module("", &module)
        .or(Err(Error::InstantiationFailed))?;

    let function = linker.get_default("").or(Err(Error::ExportNotFound))?;

    // Invoke the function.
    function.call(Default::default()).or(Err(Error::CallFailed))
}

#[cfg(test)]
pub(crate) mod test {
    use crate::workload;
    use std::iter::empty;

    #[test]
    fn workload_run_return_1() {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/fixtures/return_1.wasm")).to_vec();

        let results: Vec<i32> = workload::run(&bytes, empty::<&str>(), empty::<(&str, &str)>())
            .unwrap()
            .iter()
            .map(|v| v.unwrap_i32())
            .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/fixtures/no_export.wasm")).to_vec();

        match workload::run(&bytes, empty::<&str>(), empty::<(&str, &str)>()) {
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
            empty::<(&str, &str)>(),
        )
        .unwrap()
        .iter()
        .map(|v| v.unwrap_i32())
        .collect();

        assert_eq!(results, vec![3]);
    }
}
