// SPDX-License-Identifier: Apache-2.0

//! Utility functions for pointers

use core::mem::align_of;

/// Validates that `ptr` is aligned and non-null
///
/// Returns `Some(ptr)`, if so and `None` if not.
pub fn is_aligned_non_null<T>(ptr: usize) -> Option<usize> {
    if ptr == 0 || ptr % align_of::<T>() != 0 {
        return None;
    }
    Some(ptr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_aligned_non_null() {
        assert_eq!(super::is_aligned_non_null::<u8>(0), None);
        assert_eq!(super::is_aligned_non_null::<u64>(0), None);

        assert_eq!(
            super::is_aligned_non_null::<u8>(align_of::<u16>()),
            Some(align_of::<u16>())
        );
        assert_eq!(
            super::is_aligned_non_null::<u16>(align_of::<u16>()),
            Some(align_of::<u16>())
        );
        assert_eq!(super::is_aligned_non_null::<u32>(align_of::<u16>()), None);
        assert_eq!(super::is_aligned_non_null::<u64>(align_of::<u16>()), None);

        assert_eq!(
            super::is_aligned_non_null::<u64>(align_of::<u64>()),
            Some(align_of::<u64>())
        );
        assert_eq!(
            super::is_aligned_non_null::<u128>(align_of::<u64>()),
            Some(align_of::<u64>())
        );
    }
}
