// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![deny(clippy::all)]

use core::ops::*;

macro_rules! impltraits {
    ($($num:ty)+) => {
        $(
            impl Zero for $num {
                const ZERO: Self = 0;
            }

            impl One for $num {
                const ONE: Self = 1;
            }
        )+
    };
}

macro_rules! implfrom {
    ($name:ident) => {
        impl<T> $name<T> {
            pub const fn new(value: T) -> Self {
                Self(value)
            }

            pub fn inner(self) -> T {
                self.0
            }
        }

        impl<T> $name<T>
        where
            T: BitAnd<T, Output = T>,
            T: Add<T, Output = T>,
            T: Sub<T, Output = T>,
            T: Mul<T, Output = T>,
            T: Div<T, Output = T>,
            T: From<bool>,
            T: Copy,
            T: Zero,
            T: One,
        {
            #[inline(always)]
            pub fn align(self, up: bool, boundary: T) -> Self {
                let sum = self.0 + if up { boundary - T::ONE } else { T::ZERO };
                Self(sum / boundary * boundary)
            }
        }

        impl<T> From<T> for $name<T> {
            #[inline(always)]
            fn from(value: T) -> Self {
                Self(value)
            }
        }

        #[cfg(target_pointer_width = "64")]
        impl From<$name<u64>> for $name<usize> {
            #[inline(always)]
            fn from(value: $name<u64>) -> Self {
                Self(value.0 as _)
            }
        }

        #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
        impl From<$name<usize>> for $name<u64> {
            #[inline(always)]
            fn from(value: $name<usize>) -> Self {
                Self(value.0 as _)
            }
        }

        #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
        impl From<$name<u32>> for $name<usize> {
            #[inline(always)]
            fn from(value: $name<u32>) -> Self {
                Self(value.0 as _)
            }
        }

        #[cfg(any(target_pointer_width = "32"))]
        impl From<$name<usize>> for $name<u32> {
            #[inline(always)]
            fn from(value: $name<usize>) -> Self {
                Self(value.0 as _)
            }
        }
    };
}

impltraits! {
    u8 u16 u32 u64 u128 usize
    i8 i16 i32 i64 i128 isize
}

pub trait Zero: Copy {
    const ZERO: Self;
}

pub trait One: Copy {
    const ONE: Self;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Offset<T>(T);
implfrom!(Offset);

impl<T: Add<T, Output = T>> Add for Offset<T> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl<T: AddAssign<T>> AddAssign for Offset<T> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<T: Div<T, Output = T>> Div for Offset<T> {
    type Output = Self;

    #[inline(always)]
    fn div(self, rhs: Self) -> Self::Output {
        (self.0 / rhs.0).into()
    }
}

impl<T: DivAssign<T>> DivAssign for Offset<T> {
    #[inline(always)]
    fn div_assign(&mut self, rhs: Self) {
        self.0 /= rhs.0;
    }
}

impl<T: Mul<T, Output = T>> Mul for Offset<T> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        (self.0 * rhs.0).into()
    }
}

impl<T: MulAssign<T>> MulAssign for Offset<T> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<T: Rem<T, Output = T>> Rem for Offset<T> {
    type Output = Self;

    #[inline(always)]
    fn rem(self, rhs: Self) -> Self::Output {
        (self.0 % rhs.0).into()
    }
}

impl<T: RemAssign<T>> RemAssign for Offset<T> {
    #[inline(always)]
    fn rem_assign(&mut self, rhs: Self) {
        self.0 %= rhs.0;
    }
}

impl<T: Sub<T, Output = T>> Sub for Offset<T> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        (self.0 - rhs.0).into()
    }
}

impl<T: SubAssign<T>> SubAssign for Offset<T> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Address<T>(T);
implfrom!(Address);

impl<T: Add<T, Output = T>> Add<Offset<T>> for Address<T> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Offset<T>) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl<T: AddAssign<T>> AddAssign<Offset<T>> for Address<T> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Offset<T>) {
        self.0 += rhs.0;
    }
}

impl<T: Sub<T, Output = T>> Sub<Address<T>> for Address<T> {
    type Output = Offset<T>;

    #[inline(always)]
    fn sub(self, rhs: Address<T>) -> Self::Output {
        (self.0 - rhs.0).into()
    }
}

impl<T: Sub<T, Output = T>> Sub<Offset<T>> for Address<T> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Offset<T>) -> Self::Output {
        (self.0 - rhs.0).into()
    }
}

impl<T: SubAssign<T>> SubAssign<Offset<T>> for Address<T> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Offset<T>) {
        self.0 -= rhs.0;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn align() {
        assert_eq!(Offset::from(9).align(true, 8), Offset::from(16));
        assert_eq!(Offset::from(9).align(false, 8), Offset::from(8));

        assert_eq!(Address::from(9).align(true, 8), Address::from(16));
        assert_eq!(Address::from(9).align(false, 8), Address::from(8));
    }
}
