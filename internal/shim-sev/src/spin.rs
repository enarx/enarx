// SPDX-License-Identifier: Apache-2.0

//! wrapper around spinning types to permit trait implementations.

use spinning::{Mutex, MutexGuard, RawMutex, RawRwLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A wrapper around spinning::Mutex to permit trait implementations.
pub struct Locked<A> {
    inner: Mutex<A>,
}

impl<A> Locked<A> {
    /// Constructor
    #[inline]
    pub const fn new(inner: A) -> Self {
        Self {
            inner: Mutex::const_new(RawMutex::const_new(), inner),
        }
    }

    /// get a [`MutexGuard`](spinning::MutexGuard)
    #[inline]
    pub fn lock(&self) -> MutexGuard<A> {
        self.inner.lock()
    }
}

/// A wrapper around spinning::RwLock to permit trait implementations.
pub struct RwLocked<A> {
    inner: RwLock<A>,
}

impl<A> RwLocked<A> {
    /// Constructor
    #[inline]
    pub const fn new(inner: A) -> Self {
        Self {
            inner: RwLock::const_new(RawRwLock::const_new(), inner),
        }
    }

    /// get a [`RwLockReadGuard`](spinning::RwLockReadGuard)
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<A> {
        self.inner.read()
    }

    /// get a [`RwLockWriteGuard`](spinning::RwLockWriteGuard)
    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<A> {
        self.inner.write()
    }
}
