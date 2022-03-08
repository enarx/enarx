// SPDX-License-Identifier: Apache-2.0

//! Utility functions for pointers

/// Validates that `ptr` is aligned and non-null
///
/// Returns `Some(ptr)`, if so and `None` if not.
pub fn is_aligned_non_null<T>(ptr: usize) -> Option<usize> {
    if ptr == 0 || ptr % core::mem::align_of::<T>() != 0 {
        return None;
    }
    Some(ptr)
}
