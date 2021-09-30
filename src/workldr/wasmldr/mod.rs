// SPDX-License-Identifier: Apache-2.0

pub struct Wasmldr;

impl crate::workldr::Workldr for Wasmldr {
    #[inline]
    fn name(&self) -> &'static str {
        "wasmldr"
    }

    #[inline]
    fn exec(&self) -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/bin/wasmldr"))
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
            include_bytes!(concat!(env!("OUT_DIR"), "/bin/wasmldr"))
        );
    }
}
