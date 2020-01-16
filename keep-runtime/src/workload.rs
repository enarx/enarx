// SPDX-License-Identifier: Apache-2.0

/// The error codes of workload execution.
#[derive(Debug)]
pub enum Error {
    /// import module not found
    ImportModuleNotFound(String),
    /// import field not found
    ImportFieldNotFound(String, String),
    /// export not found
    ExportNotFound,
    /// call failed
    CallFailed,
    /// runtime error
    RuntimeError,
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
    let engine = wasmtime::Engine::default();
    let store = wasmtime::Store::new(&engine);

    // Instantiate WASI
    let mut builder = wasi_common::WasiCtxBuilder::new();
    builder.args(args).envs(envs);
    let ctx = builder.build().or(Err(Error::RuntimeError))?;
    let wasi_snapshot_preview1 = wasmtime_wasi::Wasi::new(&store, ctx);

    let instance = {
        let module = wasmtime::Module::new(&store, bytes).or(Err(Error::RuntimeError))?;
        let imports = module
            .imports()
            .map(|import| {
                let module_name = import.module();
                let field_name = import.name();
                let export = match module_name {
                    "wasi_snapshot_preview1" => Ok(wasi_snapshot_preview1.get_export(field_name)),
                    _ => Err(Error::ImportModuleNotFound(module_name.to_string())),
                }?;

                if let Some(export) = export {
                    Ok(export.clone().into())
                } else {
                    Err(Error::ImportFieldNotFound(
                        module_name.to_string(),
                        field_name.to_string(),
                    ))
                }
            })
            .collect::<Result<Vec<_>>>()?;

        wasmtime::Instance::new(&module, &imports).or(Err(Error::RuntimeError))?
    };

    let function = if instance.exports().any(|export| export.name().is_empty()) {
        // Launch the default command export.
        instance.get_func("")
    } else {
        // If the module doesn't have a default command
        // export, launch the _start function if one is
        // present, as a compatibility measure.
        instance.get_func("_start")
    }
    .ok_or(Error::ExportNotFound)?;

    // Invoke the function.
    function.call(Default::default()).or(Err(Error::CallFailed))
}

#[cfg(test)]
pub(crate) mod test {
    use crate::workload;
    use std::iter::empty;

    #[test]
    fn workload_run_return_1() {
        let path = std::path::Path::new("fixtures").join("return_1.wat");

        let bytes = wat::parse_file(&path).unwrap();

        let results: Vec<i32> = workload::run(&bytes, empty::<&str>(), empty::<(&str, &str)>())
            .unwrap()
            .iter()
            .map(|v| v.unwrap_i32())
            .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let path = std::path::Path::new("fixtures").join("no_export.wat");

        let bytes = wat::parse_file(&path).unwrap();

        match workload::run(&bytes, empty::<&str>(), empty::<(&str, &str)>()) {
            Err(workload::Error::ExportNotFound) => {}
            _ => panic!("unexpected error"),
        };
    }

    #[test]
    fn workload_run_wasi_snapshot1() {
        let path = std::path::Path::new("fixtures").join("wasi_snapshot1.wat");

        let bytes = wat::parse_file(&path).unwrap();

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
