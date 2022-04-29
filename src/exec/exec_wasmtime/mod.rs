// SPDX-License-Identifier: Apache-2.0

use crate::Backend;

pub struct WasmExec;

impl crate::exec::Exec for WasmExec {
    #[inline]
    fn name(&self) -> &'static str {
        "exec_wasmtime"
    }

    #[inline]
    fn exec(&self) -> &'static [u8] {
        include_bytes!(env!("CARGO_BIN_FILE_ENARX_EXEC_WASMTIME_BIN"))
    }

    fn with_backend(&self, backend: &dyn Backend) -> bool {
        backend.name() != "nil"
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::WasmExec;
    use crate::exec::Exec;

    // Check that wasmldr.exec() gives us the binary contents
    #[test]
    fn is_builtin() {
        let wasmldr = Box::new(WasmExec);
        assert_eq!(
            wasmldr.exec(),
            include_bytes!(env!("CARGO_BIN_FILE_ENARX_EXEC_WASMTIME_BIN"))
        );
    }
}
