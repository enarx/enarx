// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use wasi_common::virtfs::VirtualDirEntry;
use wasmparser::{Chunk, Parser, Payload::*};

const RESOURCES_SECTION: &str = ".enarx.resources";

/// The error codes of workload execution.
#[derive(Debug)]
pub enum Error {
    /// invalid workload format
    InvalidFormat,
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

fn populate_entry<R: Read>(mut dir: &mut VirtualDirEntry, entry: &mut tar::Entry<R>) -> Result<()> {
    match entry.header().entry_type() {
        tar::EntryType::Regular => {
            let path = entry.header().path()?;
            let parent = {
                if let Some(parent) = path.parent() {
                    crate::virtfs::populate_directory(&mut dir, parent)
                        .or(Err(Error::InvalidFormat))?
                } else {
                    dir
                }
            };

            match parent {
                VirtualDirEntry::Directory(ref mut map) => {
                    let name = path.file_name().unwrap().to_str().unwrap().to_string();
                    let mut content: Vec<u8> = Vec::new();
                    entry.read_to_end(&mut content)?;
                    let content = crate::virtfs::VecFileContents::new(content);
                    map.insert(name, VirtualDirEntry::File(Box::new(content)));
                }
                _ => unreachable!(),
            }
        }
        tar::EntryType::Directory => {
            let path = entry.header().path()?;
            let _ =
                crate::virtfs::populate_directory(&mut dir, path).or(Err(Error::InvalidFormat))?;
        }
        _ => {}
    }
    Ok(())
}

fn populate_virtfs(root: &mut VirtualDirEntry, bytes: &[u8]) -> Result<()> {
    let mut offset: usize = 0;
    let mut parser = Parser::new(offset as u64);
    loop {
        let (consumed, payload) = match parser
            .parse(&bytes[offset..], true)
            .or(Err(Error::RuntimeError))?
        {
            Chunk::Parsed { consumed, payload } => (consumed, payload),
            // this state isn't possible with `eof = true`
            Chunk::NeedMoreData(_) => unreachable!(),
        };

        offset += consumed;

        match payload {
            End => break,
            CustomSection { name, data, .. } if name == RESOURCES_SECTION => {
                let mut ar = tar::Archive::new(data);
                for entry in ar.entries()? {
                    let mut entry = entry?;
                    populate_entry(root, &mut entry)?;
                }
            }
            CodeSectionStart { size, .. } | ModuleCodeSectionStart { size, .. } => {
                parser.skip_section();
                offset += size as usize;
            }
            _ => {}
        }
    }
    Ok(())
}

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

    // Instantiate WASI
    let mut builder = wasi_common::WasiCtxBuilder::new();
    builder.args(args).envs(envs);
    let mut root = VirtualDirEntry::empty_directory();
    populate_virtfs(&mut root, bytes.as_ref())?;
    builder.preopened_virt(root, ".");
    let ctx = builder.build().or(Err(Error::RuntimeError))?;
    let wasi_snapshot_preview1 = wasmtime_wasi::Wasi::new(&store, ctx);

    let instance = {
        let module = wasmtime::Module::from_binary(&store.engine(), bytes.as_ref())
            .or(Err(Error::RuntimeError))?;
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

        wasmtime::Instance::new(&store, &module, &imports).or(Err(Error::RuntimeError))?
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
