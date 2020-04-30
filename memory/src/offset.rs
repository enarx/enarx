// SPDX-License-Identifier: Apache-2.0

use super::*;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::*;

/// An offset of a number of items of type `T` from a base
///
/// Note well that this is NOT stored in memory as the number of bytes,
/// but rather the number of items.
///
/// One important additional feature is that offsets can be converted between
/// underlying types so long as the conversion is lossless for the target CPU
/// architecture. For example, `Offset<u64>` can be converted to
/// `Offset<usize>` on 64-bit systems.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Offset<T, U>(T, PhantomData<U>);

impl<T, U> Offset<T, U> {
    /// Create an offset value from the number of items
    #[inline]
    pub const fn from_items(items: T) -> Self {
        Self(items, PhantomData)
    }

    /// Get the number of items
    #[inline]
    pub fn items(self) -> T {
        self.0
    }
}

impl<T, U> Offset<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Mul<T, Output = T>,
{
    /// Get the number of bytes
    #[inline]
    pub fn bytes(self) -> T {
        self.0 * Offset(size_of::<U>(), PhantomData).into().items()
    }
}

impl<T: Zero, U: Copy> Zero for Offset<T, U> {
    const ZERO: Offset<T, U> = Offset::from_items(T::ZERO);
}

impl<T: One, U: Copy> One for Offset<T, U> {
    const ONE: Offset<T, U> = Offset::from_items(T::ONE);
}

impl<T, U> From<Register<T>> for Offset<T, U> {
    #[inline]
    fn from(value: Register<T>) -> Self {
        Self::from_items(value.raw())
    }
}

impl<T, U> From<Offset<T, U>> for Register<T> {
    #[inline]
    fn from(value: Offset<T, U>) -> Self {
        Self::from_raw(value.0)
    }
}

#[cfg(target_pointer_width = "64")]
impl<U> From<Offset<u64, U>> for Offset<usize, U> {
    #[inline]
    fn from(value: Offset<u64, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl<U> From<Offset<usize, U>> for Offset<u64, U> {
    #[inline]
    fn from(value: Offset<usize, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl<U> From<Offset<u32, U>> for Offset<usize, U> {
    #[inline]
    fn from(value: Offset<u32, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

#[cfg(target_pointer_width = "32")]
impl<U> From<Offset<usize, U>> for Offset<u32, U> {
    #[inline]
    fn from(value: Offset<usize, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

impl<T: Add<T, Output = T>, U> Add for Offset<T, U> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, PhantomData)
    }
}

impl<T: AddAssign<T>, U> AddAssign for Offset<T, U> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<T: Div<T, Output = T>, U> Div for Offset<T, U> {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0 / rhs.0, PhantomData)
    }
}

impl<T: DivAssign<T>, U> DivAssign for Offset<T, U> {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        self.0 /= rhs.0;
    }
}

impl<T: Mul<T, Output = T>, U> Mul for Offset<T, U> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0, PhantomData)
    }
}

impl<T: MulAssign<T>, U> MulAssign for Offset<T, U> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<T: Rem<T, Output = T>, U> Rem for Offset<T, U> {
    type Output = Self;

    #[inline]
    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.0 % rhs.0, PhantomData)
    }
}

impl<T: RemAssign<T>, U> RemAssign for Offset<T, U> {
    #[inline]
    fn rem_assign(&mut self, rhs: Self) {
        self.0 %= rhs.0;
    }
}

impl<T: Sub<T, Output = T>, U> Sub for Offset<T, U> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, PhantomData)
    }
}

impl<T: SubAssign<T>, U> SubAssign for Offset<T, U> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}
