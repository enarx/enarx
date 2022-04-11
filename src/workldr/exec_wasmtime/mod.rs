// SPDX-License-Identifier: Apache-2.0

pub struct Wasmldr;

impl crate::workldr::Workldr for Wasmldr {
    #[inline]
    fn name(&self) -> &'static str {
        "exec_wasmtime"
    }

    #[inline]
    fn exec(&self) -> &'static [u8] {
        include_bytes!(env!("CARGO_BIN_FILE_ENARX_EXEC_WASMTIME"))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::Wasmldr;
    use crate::workldr::Workldr;

    // Check that wasmldr.exec() gives us the binary contents
    #[test]
    fn is_builtin() {
        let wasmldr = Box::new(Wasmldr);
        assert_eq!(
            wasmldr.exec(),
            include_bytes!(env!("CARGO_BIN_FILE_ENARX_EXEC_WASMTIME"))
        );
    }
}
