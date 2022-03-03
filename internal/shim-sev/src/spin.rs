// SPDX-License-Identifier: Apache-2.0

//! wrapper around spinning types to permit trait implementations.

use core::cell::UnsafeCell;
use spinning::{Mutex, MutexGuard, RawMutex, RawRwLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Cell type that should be preferred over a `static mut` is better to use in a
/// `static`
///
/// Based on [@bstrie comment](issue-53639-bstrie)
/// [issue-53639-bstrie]: https://github.com/rust-lang/rust/issues/53639#issuecomment-888435728
///
/// # Safety
///
/// The idea here being that callers of `RacyCell::get` could only turn that *mut into a reference,
/// if you can guarantee the usual reference safety invariants as demonstrated in
/// [this example for UnsafeCell::get](https://doc.rust-lang.org/std/cell/struct.UnsafeCell.html#examples),
/// with the added rub that you also have to uphold those invariants while taking threads into account,
/// which means that almost nobody can actually safely cast this *mut to a reference
/// (which helps to illustrate the problem with static mut here),
/// so you're better off just working with the raw pointer
/// (ideally by wrapping it in your own synchronization logic).
#[repr(transparent)]
pub struct RacyCell<T>(UnsafeCell<T>);

impl<T> RacyCell<T> {
    /// Create a new RacyCell
    pub const fn new(value: T) -> Self {
        RacyCell(UnsafeCell::new(value))
    }

    /// Gets a mutable pointer to the wrapped value.
    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}

unsafe impl<T: Sync> Sync for RacyCell<T> {}

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
    pub fn lock(&self) -> MutexGuard<'_, A> {
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
    pub fn read(&self) -> RwLockReadGuard<'_, A> {
        self.inner.read()
    }

    /// get a [`RwLockWriteGuard`](spinning::RwLockWriteGuard)
    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, A> {
        self.inner.write()
    }
}
