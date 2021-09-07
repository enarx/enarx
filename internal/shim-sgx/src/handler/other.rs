// SPDX-License-Identifier: Apache-2.0

use super::Handler;

use sallyport::syscall::{NetworkSyscallHandler, SyscallHandler, SystemSyscallHandler};
use sallyport::untrusted::AddressValidator;

impl<'a> NetworkSyscallHandler for Handler<'a> {}
impl<'a> SystemSyscallHandler for Handler<'a> {}
impl<'a> SyscallHandler for Handler<'a> {}

impl<'a> AddressValidator for Handler<'a> {
    fn validate_const_mem_fn(&self, _ptr: *const (), _size: usize) -> bool {
        // FIXME: https://github.com/enarx/enarx/issues/630
        true
    }

    fn validate_mut_mem_fn(&self, _ptr: *mut (), _size: usize) -> bool {
        // FIXME: https://github.com/enarx/enarx/issues/630
        true
    }
}
