// SPDX-License-Identifier: Apache-2.0

/// A register
///
/// This type is intended to be used wherever raw access to a register value
/// is required. The type itself is opaque, but it can be converted to usable
/// types.
///
/// One important additional feature is that registers can be converted between
/// underlying types so long as the conversion is lossless for the target CPU
/// architecture. For example, `Register<u64>` can be converted to
/// `Register<usize>` on 64-bit systems.
#[derive(Copy, Clone, Debug, Default)]
#[repr(transparent)]
pub struct Register<T>(T);

impl<T> Register<T> {
    /// Create a `Register` value from the raw contents
    pub fn from_raw(value: T) -> Self {
        Self(value)
    }

    /// Returns the raw value
    pub fn raw(self) -> T {
        self.0
    }
}

#[cfg(target_pointer_width = "64")]
impl From<Register<u64>> for Register<usize> {
    #[inline]
    fn from(value: Register<u64>) -> Self {
        Self(value.0 as _)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<Register<usize>> for Register<u64> {
    #[inline]
    fn from(value: Register<usize>) -> Self {
        Self(value.0 as _)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<Register<u32>> for Register<usize> {
    #[inline]
    fn from(value: Register<u32>) -> Self {
        Self(value.0 as _)
    }
}

#[cfg(target_pointer_width = "32")]
impl From<Register<usize>> for Register<u32> {
    #[inline]
    fn from(value: Register<usize>) -> Self {
        Self(value.0 as _)
    }
}
