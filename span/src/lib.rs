// SPDX-License-Identifier: Apache-2.0

//! This crate contains types for measuring linear sets by either the end
//! points (`Bounds`) or by a starting point and the number of elements (`Span`).
//!
//! In the interest of zero-cost abstractions, all methods are always inlined
//! for maximum compiler optimization. Thus, you only pay for the conversions
//! that are actually used.

#![no_std]
#![deny(clippy::all)]
#![deny(missing_docs)]

mod line;
mod span;

pub use line::Line;
pub use span::Span;

/// Determines whether a set contains an element
pub trait Contains<T> {
    /// Returns whether or not the set contains the element
    fn contains(&self, value: &T) -> bool;
}

/// A trait for determining whether a set is empty
pub trait Empty {
    /// Returns whether or not the set is empty
    fn is_empty(&self) -> bool;
}

/// Splits the set
pub trait Split<T>: Sized {
    /// Splits the set
    ///
    /// Returns `None` if `at` is not in the set.
    fn split(self, at: T) -> Option<(Self, Self)>;
}
