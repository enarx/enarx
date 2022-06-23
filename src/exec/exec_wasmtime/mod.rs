// SPDX-License-Identifier: Apache-2.0

use crate::backend::Backend;

pub struct WasmExec;

impl crate::exec::Exec for WasmExec {
    #[inline]
    fn name(&self) -> &'static str {
        "exec_wasmtime"
    }

    #[inline]
    fn exec(&self) -> &'static [u8] {
        include_bytes!(env!("CARGO_BIN_FILE_ENARX_EXEC_WASMTIME"))
    }

    fn with_backend(&self, backend: &dyn Backend) -> bool {
        backend.name() != "nil"
    }
}
