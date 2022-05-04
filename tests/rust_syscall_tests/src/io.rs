// SPDX-License-Identifier: Apache-2.0

//! Traits, helpers, and type definitions for core I/O functionality.

use core::fmt;

struct Stdio<const FD: i32>;

impl<const FD: i32> fmt::Write for Stdio<FD> {
    #[inline(always)]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        super::write(FD, s.as_ptr(), s.len()).map_err(|_| fmt::Error)?;
        Ok(())
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _eprint(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    Stdio::<2>.write_fmt(args).unwrap();
}

#[doc(hidden)]
#[inline(always)]
pub fn _print(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    Stdio::<1>.write_fmt(args).unwrap();
}
