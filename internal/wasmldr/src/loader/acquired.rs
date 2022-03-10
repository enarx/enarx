// SPDX-License-Identifier: Apache-2.0

use super::{Acquired, Compiled, Loader};

use anyhow::Result;
use wasmtime_wasi::WasiCtxBuilder;

impl Loader<Acquired> {
    pub fn next(self) -> Result<Loader<Compiled>> {
        // Set up the wasmtime config.
        let mut config = wasmtime::Config::new();
        config.wasm_module_linking(true);
        config.wasm_multi_memory(true);
        config.static_memory_maximum_size(0);
        config.static_memory_guard_size(0);
        config.dynamic_memory_guard_size(0);
        config.dynamic_memory_reserved_for_growth(16 * 1024 * 1024);

        // Create the execution engine.
        let engine = wasmtime::Engine::new(&config)?;

        // Set up the linker and add WASI.
        let mut linker = wasmtime::Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;

        // Create the store.
        let mut wstore = wasmtime::Store::new(&engine, WasiCtxBuilder::new().build());

        // Compile and link the module.
        let module = wasmtime::Module::from_binary(&engine, &self.0.webasm)?;
        linker.module(&mut wstore, "", &module)?;

        Ok(Loader(Compiled {
            config: self.0.config,
            srvcfg: self.0.srvcfg,
            cltcfg: self.0.cltcfg,

            wstore,
            linker,
        }))
    }
}
