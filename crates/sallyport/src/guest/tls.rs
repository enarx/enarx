// SPDX-License-Identifier: Apache-2.0

use crate::item::syscall::sigaction;

use core::ffi::c_int;

pub(super) const SIGRTMAX: c_int = 64;

/// Thread-local storage shared between [`Handler`](super::Handler) instances.
pub struct ThreadLocalStorage {
    pub(super) actions: [Option<sigaction>; SIGRTMAX as _],
}

impl ThreadLocalStorage {
    #[inline]
    pub const fn new() -> Self {
        Self {
            actions: [None; SIGRTMAX as _],
        }
    }
}

impl Default for ThreadLocalStorage {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
