// SPDX-License-Identifier: Apache-2.0

//! lazy_static! replacement
//!
//! Inspired, partially copied, and adopted to `spinning`
//! from https://github.com/matklad/once_cell
//! and `std::lazy::Lazy`

use core::cell::Cell;
use core::ops::Deref;
use spinning::{Once, OnceState};

/// A value which is initialized on the first access.
///
/// This type is thread-safe and can be used in statics.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
///
/// use spinning::Lazy;
///
/// static HASHMAP: Lazy<HashMap<i32, String>> = Lazy::new(|| {
///     println!("initializing");
///     let mut m = HashMap::new();
///     m.insert(13, "Spica".to_string());
///     m.insert(74, "Hoyten".to_string());
///     m
/// });
///
/// fn main() {
///     println!("ready");
///     std::thread::spawn(|| {
///         println!("{:?}", HASHMAP.get(&13));
///     }).join().unwrap();
///     println!("{:?}", HASHMAP.get(&74));
///
///     // Prints:
///     //   ready
///     //   initializing
///     //   Some("Spica")
///     //   Some("Hoyten")
/// }
/// ```
pub struct Lazy<T, F = fn() -> T> {
    once: Once<T>,
    init: Cell<Option<F>>,
}

// We never create a `&F` from a `&Lazy<T, F>` so it is fine
// to not impl `Sync` for `F`
// we do create a `&mut Option<F>` in `force`, but this is
// properly synchronized, so it only happens once
// so it also does not contribute to this impl.
unsafe impl<T, F: Send> Sync for Lazy<T, F> where Once<T>: Sync {}
// auto-derived `Send` impl is OK.

impl<T, F> Lazy<T, F> {
    /// Creates a new lazy value with the given initializing
    /// function.
    #[inline(always)]
    pub const fn new(f: F) -> Lazy<T, F> {
        Lazy {
            once: Once::new(),
            init: Cell::new(Some(f)),
        }
    }
}

impl<T, F: FnOnce() -> T> Lazy<T, F> {
    /// Forces the evaluation of this lazy value and
    /// returns a reference to the result. This is equivalent
    /// to the `Deref` impl, but is explicit.
    ///
    /// # Example
    /// ```
    /// use spinning::Lazy;
    ///
    /// let lazy = Lazy::new(|| 92);
    ///
    /// assert_eq!(Lazy::force(&lazy), &92);
    /// assert_eq!(&*lazy, &92);
    /// ```
    #[inline(always)]
    pub fn force(this: &Lazy<T, F>) -> &T {
        this.once.call_once(|| match this.init.take() {
            Some(f) => f(),
            None => panic!("Lazy instance has previously been poisoned"),
        })
    }

    /// Get the current state
    pub fn state(&self) -> OnceState {
        self.once.state()
    }
}

impl<T, F: FnOnce() -> T> Deref for Lazy<T, F> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        Lazy::force(self)
    }
}

impl<T: Default> Default for Lazy<T> {
    /// Creates a new lazy value using `Default` as the initializing function.
    #[inline(always)]
    fn default() -> Lazy<T> {
        Lazy::new(T::default)
    }
}
