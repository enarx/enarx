// SPDX-License-Identifier: Apache-2.0

use libc::{c_int, sigaction};

pub(super) const SIGRTMAX: c_int = 64;

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
