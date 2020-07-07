// SPDX-License-Identifier: Apache-2.0

use super::*;
use core::marker::PhantomData;
use core::mem::align_of;
use core::ops::*;

/// An address
///
/// This newtype is used to represent addresses of a given type.
/// The most important invariant of this type is that the address is always
/// properly aligned for the given type `U`. The only way to convert between
/// addresses of different types is to choose a new alignment (raise or lower).
///
/// This type does *not*, however, track lifetime. You're on your own.
///
/// Unlike the naked underlying types, you can infallibly convert between,
/// for example, an `Address<usize, ()>` and an `Address<u64, ()>` wherever
/// such a conversion is lossless given the target CPU architecture.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Address<T, U>(T, PhantomData<U>);

impl<T: Zero, U: Copy> Address<T, U> {
    /// The NULL address
    pub const NULL: Address<T, U> = Address(T::ZERO, PhantomData);
}

impl<T, U> Address<T, U> {
    /// Create a new `Address` from a raw inner type without checking
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not enforce the main constraint
    /// of this type that the address stored is properly aligned to the type.
    ///
    /// For a safe version of this constructor, first create an `Address<T, ()>`
    /// from the raw value and then align to the type you want.
    #[inline]
    pub const unsafe fn unchecked(value: T) -> Self {
        Self(value, PhantomData)
    }

    /// Converts an `Address` to its raw inner type
    #[inline]
    pub fn raw(self) -> T {
        self.0
    }
}

impl<T, U> Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Rem<T, Output = T>,
    T: Zero,
    T: PartialEq,
{
    /// Try casting an existing `Address` into an `Address` of a different type
    ///
    /// Succeeds only, if they have the same alignment
    #[inline]
    pub fn try_cast<V>(self) -> Result<Address<T, V>, ()> {
        let align: T = Offset::from_items(align_of::<V>()).into().items();
        if self.0 % align != T::ZERO {
            return Err(());
        }
        Ok(Address(self.0, PhantomData))
    }
}

impl<T, U> Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Add<T, Output = T>,
    T: Sub<T, Output = T>,
    T: Mul<T, Output = T>,
    T: Div<T, Output = T>,
    T: One,
{
    /// Cast an existing `Address` into an `Address` of a different type by aligning up
    #[inline]
    pub fn raise<V>(self) -> Address<T, V> {
        let align: T = Offset::from_items(align_of::<V>()).into().items();
        Address((self.0 + align - T::ONE) / align * align, PhantomData)
    }

    /// Cast an existing `Address` into an `Address` of a different type by aligning down
    #[inline]
    pub fn lower<V>(self) -> Address<T, V> {
        let align: T = Offset::from_items(align_of::<V>()).into().items();
        Address(self.0 / align * align, PhantomData)
    }
}

/// Convert a raw address value to an untyped `Address`
impl<T> From<T> for Address<T, ()> {
    #[inline]
    fn from(value: T) -> Self {
        Self(value, PhantomData)
    }
}

/// Convert a reference to an `Address` with the same type
impl<T, U> From<&U> for Address<T, U>
where
    Address<usize, U>: Into<Address<T, U>>,
{
    #[inline]
    fn from(value: &U) -> Self {
        Address(value as *const U as usize, PhantomData).into()
    }
}

/// Convert a mutable pointer to an `Address` with the same type
impl<T, U> From<*mut U> for Address<T, U>
where
    Address<usize, U>: Into<Address<T, U>>,
{
    #[inline]
    fn from(value: *mut U) -> Self {
        Address(value as usize, PhantomData).into()
    }
}

/// Convert a const pointer to an `Address` with the same type
impl<T, U> From<*const U> for Address<T, U>
where
    Address<usize, U>: Into<Address<T, U>>,
{
    #[inline]
    fn from(value: *const U) -> Self {
        Address(value as usize, PhantomData).into()
    }
}

// Convert from a `Register` to an untyped `Address`.
impl<T: From<Register<T>>> From<Register<T>> for Address<T, ()> {
    #[inline]
    fn from(value: Register<T>) -> Self {
        Self::from(T::from(value))
    }
}

// Convert from an `Address` to a `Register`, discarding type.
impl<T, U> From<Address<T, U>> for Register<T>
where
    Register<T>: From<T>,
{
    #[inline]
    fn from(value: Address<T, U>) -> Self {
        Self::from(value.0)
    }
}

#[cfg(target_pointer_width = "64")]
impl<U> From<Address<u64, U>> for Address<usize, U> {
    #[inline]
    fn from(value: Address<u64, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl<U> From<Address<usize, U>> for Address<u64, U> {
    #[inline]
    fn from(value: Address<usize, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl<U> From<Address<u32, U>> for Address<usize, U> {
    #[inline]
    fn from(value: Address<u32, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

#[cfg(target_pointer_width = "32")]
impl<U> From<Address<usize, U>> for Address<u32, U> {
    #[inline]
    fn from(value: Address<usize, U>) -> Self {
        Self(value.0 as _, PhantomData)
    }
}

impl<T, U> Add<Offset<T, U>> for Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Mul<T, Output = T>,
    T: Add<T, Output = T>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Offset<T, U>) -> Self::Output {
        Self(self.0 + rhs.bytes(), PhantomData)
    }
}

impl<T, U> AddAssign<Offset<T, U>> for Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Mul<T, Output = T>,
    T: AddAssign<T>,
{
    #[inline]
    fn add_assign(&mut self, rhs: Offset<T, U>) {
        self.0 += rhs.bytes();
    }
}

impl<T, U> Sub<Address<T, U>> for Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Mul<T, Output = T>,
    T: Sub<T, Output = T>,
    T: Div<T, Output = T>,
    T: One,
{
    type Output = Offset<T, U>;

    #[inline]
    fn sub(self, rhs: Address<T, U>) -> Self::Output {
        let offset: Offset<T, U> = Offset::from_items(T::ONE);
        Offset::from_items((self.0 - rhs.0) / offset.bytes())
    }
}

impl<T, U> Sub<Offset<T, U>> for Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Mul<T, Output = T>,
    T: Sub<T, Output = T>,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Offset<T, U>) -> Self::Output {
        Self(self.0 - rhs.bytes(), PhantomData)
    }
}

impl<T, U> SubAssign<Offset<T, U>> for Address<T, U>
where
    Offset<usize, ()>: Into<Offset<T, ()>>,
    T: Mul<T, Output = T>,
    T: SubAssign<T>,
{
    #[inline]
    fn sub_assign(&mut self, rhs: Offset<T, U>) {
        self.0 -= rhs.bytes();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn align() {
        assert_eq!(Address::from(9usize).raise::<u64>().raw(), 16);
        assert_eq!(Address::from(9usize).lower::<u64>().raw(), 8);
        assert_eq!(Address::from(7usize).raise::<u32>().raw(), 8);
        assert_eq!(Address::from(7usize).lower::<u32>().raw(), 4);
    }
}
