// SPDX-License-Identifier: Apache-2.0

//! The Workload module implements retrieving and running WASM workloads.

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasmtime::Val;

/// Struct to hold and process the workload
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    modules: HashMap<String, Box<[u8]>>,
    function: Function,
}

/// Struct to specify what function to call and what to pass
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Function {
    module: String,
    name: String,
    args: Box<[String]>,
}

impl<'a> Workload {
    /// Construct a new Workload with the given values.
    pub fn new(
        modules: HashMap<String, Box<[u8]>>,
        function_module: String,
        function_name: String,
        function_args: Box<[String]>,
    ) -> Self {
        Self {
            modules,
            function: Function {
                module: function_module,
                name: function_name,
                args: function_args,
            },
        }
    }

    /// Retrieves a serialized WASM workload from a Reader.
    pub fn deserialize_from_reader<R: std::io::Read>(r: R) -> Result<Self> {
        serde_json::from_reader(r).map_err(Into::into)
    }

    /// Runs an initialized workload, allowing to override the parameter with the given options
    pub fn run(
        &self,
        function_module: Option<&str>,
        function_name: Option<&str>,
        function_args: Option<&[Val]>,
    ) -> Result<Box<[Val]>> {
        let function_name = function_name.unwrap_or(&self.function.name);

        // Wasmtime API and helper variables
        let engine = wasmtime::Engine::default();
        let store = wasmtime::Store::new(&engine);
        let mut module_registry: HashMap<String, wasmtime::Instance> = HashMap::new();

        // Instantiate WASI
        let wasi = wasmtime_wasi::instantiate_wasi(
            // preopened_dirs: &[(String, File)],
            Default::default(),
            // argv: &[String],
            Default::default(),
            // environ: &[(String, String)],
            Default::default(),
        )
        .expect("couldn't instantiate WASI");
        module_registry.insert(
            "wasi_unstable".to_string(),
            wasmtime::Instance::from_handle(&store, wasi),
        );

        let instance = {
            // Resolve the app_module imports using the module_registry.
            // TODO: process all workload data
            let module_name = function_module.unwrap_or(&self.function.module);
            let app_module = wasmtime::Module::new_with_name(
                &store,
                &self
                    .modules
                    .get(module_name)
                    .ok_or_else(|| "workload data is empty".to_string())?,
                module_name,
            )?;
            let imports = app_module
                .imports()
                .iter()
                .map(|import| {
                    let module_name = import.module();
                    if let Some(instance) = module_registry.get(module_name) {
                        let field_name = import.name();
                        if let Some(export) = instance.get_export(field_name) {
                            Ok(export.clone())
                        } else {
                            Err(format!(
                                "Import {} was not found in module {}",
                                field_name, module_name
                            ))
                        }
                    } else {
                        Err(format!("Import module {} was not found", module_name))
                    }
                    .map_err(Into::into)
                })
                .collect::<Result<Vec<_>>>()?;

            wasmtime::Instance::new(&app_module, &imports)?
        };

        let function = instance
            .get_export(&function_name)
            .ok_or_else(|| format!("could not find export {}", &function_name))?
            .func()
            .ok_or_else(|| format!("export {} is not a function", &function_name))?;

        // Invoke the function
        function
            .call(function_args.unwrap_or(
                // TODO: parse and use self.function_args here
                Default::default(),
            ))
            .map_err(Into::into)
    }
}

/// Trait to model the functionality for retrieving the WASM workload.
pub trait WorkloadReader {
    /// Instantiate a workload Reader
    fn get_reader(&self) -> Result<Box<dyn std::io::Read>>;
}

/// Retrieve the workload from a raw unux filedescriptor
#[cfg(target_os = "linux")]
pub mod fd_workload_reader {
    use super::Result;

    use std::{fs::File, os::unix::io::FromRawFd};

    /// Struct to implement workload retrieving from a file-descriptor.
    pub struct FdWorkloadReader(i32);
    impl FdWorkloadReader {
        /// Instantiate a new FdWorkloadRetriever with with the given file descriptor
        pub fn new(fd: i32) -> Self {
            Self(fd)
        }
    }

    impl super::WorkloadReader for FdWorkloadReader {
        fn get_reader(&self) -> Result<Box<dyn std::io::Read>> {
            Ok(Box::new(unsafe { File::from_raw_fd(self.0) }))
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::WorkloadReader;

        #[test]
        fn inmemory_roundtrip() {
            use std::io::Seek;
            use std::os::unix::io::AsRawFd;

            let workload = crate::workload::test::util::get_workload_from_fixtures(
                &["return_1.wasm"],
                "return_1.wasm",
                "main",
                &[],
            )
            .unwrap();

            let mut workload_serialized_file = tempfile::tempfile().unwrap();
            serde_json::to_writer(&workload_serialized_file, &workload).unwrap();
            workload_serialized_file
                .seek(std::io::SeekFrom::Start(0))
                .unwrap();

            let fd = workload_serialized_file.as_raw_fd();
            let reader = super::FdWorkloadReader::new(fd).get_reader().unwrap();

            let workload_deserialized =
                crate::workload::Workload::deserialize_from_reader(reader).unwrap();
            assert_eq!(workload, workload_deserialized);
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use util::*;

    pub(crate) mod util {
        use super::*;

        pub(crate) fn get_workload_from_fixtures(
            fixtures: &[&str],
            function_fixture: &str,
            function_name: &str,
            function_args: &[&str],
        ) -> Result<Workload> {
            use std::io::Read;

            let mut modules = HashMap::new();
            for fixture in fixtures {
                let mut fixture_buf = Vec::new();
                let mut fixture_file = std::fs::File::open(format!("fixtures/{}", fixture))?;
                fixture_file.read_to_end(&mut fixture_buf)?;
                modules.insert((*fixture).to_string(), fixture_buf.into_boxed_slice());
            }

            Ok(Workload::new(
                modules,
                function_fixture.to_string(),
                function_name.to_string(),
                function_args
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ))
        }

        pub(super) fn serialize_workload(workload: &Workload) -> Result<Box<[u8]>> {
            serde_json::to_vec(workload)
                .map(Vec::into_boxed_slice)
                .map_err(Into::into)
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deserialize_from_file() {
        let f = std::fs::File::open("fixtures/return_1.wkld").unwrap();
        Workload::deserialize_from_reader(f).unwrap();
    }

    #[test]
    fn deserialize_workload_from_fixture() {
        let workload =
            get_workload_from_fixtures(&["return_1.wasm"], "return_1.wasm", "main", &[]).unwrap();

        let serialized_workload = serialize_workload(&workload).unwrap();

        let deserialized_workload =
            Workload::deserialize_from_reader(serialized_workload.as_ref()).unwrap();

        assert_eq!(workload, deserialized_workload);
    }

    #[test]
    fn workload_run_return_1() {
        let workload =
            get_workload_from_fixtures(&["return_1.wasm"], "return_1.wasm", "main", &[]).unwrap();

        let results: Vec<i32> = workload
            .run(None, None, None)
            .unwrap()
            .iter()
            .map(|v| v.unwrap_i32())
            .collect();

        assert_eq!(results, vec![1]);
    }
}
