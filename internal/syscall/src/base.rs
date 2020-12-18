// SPDX-License-Identifier: Apache-2.0

//! basic syscall handler functions

use primordial::Register;
use sallyport::{Cursor, Request, Result};

/// basic syscall handler functions
pub trait BaseSyscallHandler {
    /// Proxy a syscall `Request`
    ///
    /// # Safety
    /// The caller has to ensure valid parameters.
    unsafe fn proxy(&mut self, req: Request) -> Result;

    /// Called, when the host might want to attack us, giving
    /// the shim bogus values
    fn attacked(&mut self) -> !;

    /// Translates a shim virtual address to the host virtual address
    fn translate_shim_to_host_addr<T>(buf: *const T) -> usize;

    /// Returns a new `Cursor` for the sallyport `Block`
    fn new_cursor(&mut self) -> Cursor;

    /// Report an unknown syscall
    #[allow(clippy::too_many_arguments)]
    fn unknown_syscall(
        &mut self,
        a: Register<usize>,
        b: Register<usize>,
        c: Register<usize>,
        d: Register<usize>,
        e: Register<usize>,
        f: Register<usize>,
        nr: usize,
    );

    /// Output tracing information about the syscall
    fn trace(&mut self, name: &str, argc: usize);
}
