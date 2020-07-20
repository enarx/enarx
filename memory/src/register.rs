// SPDX-License-Identifier: Apache-2.0

macro_rules! implfrom {
    () => {};

    ($attr:meta $f:ident => Register<$t:ident>) => {
        #[$attr]
        impl From<$f> for Register<$t> {
            #[inline]
            fn from(value: $f) -> Self {
                Self(value as _)
            }
        }
    };

    ($attr:meta Register<$f:ident> => $t:ident) => {
        #[$attr]
        impl From<Register<$f>> for $t {
            #[inline]
            fn from(value: Register<$f>) -> Self {
                value.0 as _
            }
        }
    };

    ($attr:meta Register<$f:ident> => Register<$t:ident>) => {
        #[$attr]
        impl From<Register<$f>> for Register<$t> {
            #[inline]
            fn from(value: Register<$f>) -> Self {
                Self(value.0 as _)
            }
        }
    };

    (@try $attr:meta Register<$f:ident> => Register<$t:ident>) => {
        #[$attr]
        impl core::convert::TryFrom<Register<$f>> for Register<$t> {
            type Error = core::num::TryFromIntError;

            #[inline]
            fn try_from(value: Register<$f>) -> Result<Register<$t>, Self::Error> {
                Ok(Self(core::convert::TryFrom::try_from(value.0)?))
            }
        }
    };

    (@try $attr:meta Register<$f:ident> => $t:ident) => {
        #[$attr]
        impl core::convert::TryFrom<Register<$f>> for $t {
            type Error = core::num::TryFromIntError;

            #[inline]
            fn try_from(value: Register<$f>) -> Result<Self, Self::Error> {
                core::convert::TryFrom::try_from(value.0)
            }
        }
    };

    ($tu:ident:$ts:ident [$($lu:ident:$ls:ident)*] $($su:ident:$ss:ident)?, $($next:tt)*) => {
        implfrom! { #[allow(missing_docs)] $tu:$ts [$($lu:$ls)*] $($su:$ss)?, $($next)* }
    };

    (#[$attr:meta] $tu:ident:$ts:ident [$($lu:ident:$ls:ident)*] $($su:ident:$ss:ident)?, $($next:tt)*) => {
        implfrom! { $attr $tu => Register<$tu> }
        implfrom! { $attr $ts => Register<$tu> }
        implfrom! { $attr $tu => Register<$ts> }
        implfrom! { $attr $ts => Register<$ts> }

        implfrom! { $attr Register<$tu> => $tu }
        implfrom! { $attr Register<$ts> => $tu }
        implfrom! { $attr Register<$tu> => $ts }
        implfrom! { $attr Register<$ts> => $ts }

        implfrom! { $attr Register<$tu> => Register<$ts> }
        implfrom! { $attr Register<$ts> => Register<$tu> }

        $(
            implfrom! { $attr Register<$tu> => Register<$lu> }
            implfrom! { $attr $tu => Register<$lu> }
            implfrom! { @try $attr Register<$lu> => Register<$tu> }
            implfrom! { @try $attr Register<$lu> => $tu }

            implfrom! { $attr Register<$ts> => Register<$lu> }
            implfrom! { $attr $ts => Register<$lu> }
            implfrom! { @try $attr Register<$lu> => Register<$ts> }
            implfrom! { @try $attr Register<$lu> => $ts }

            implfrom! { $attr Register<$tu> => Register<$ls> }
            implfrom! { $attr $tu => Register<$ls> }
            implfrom! { @try $attr Register<$ls> => Register<$tu> }
            implfrom! { @try $attr Register<$ls> => $tu }

            implfrom! { $attr Register<$ts> => Register<$ls> }
            implfrom! { $attr $ts => Register<$ls> }
            implfrom! { @try $attr Register<$ls> => Register<$ts> }
            implfrom! { @try $attr Register<$ls> => $ts }
        )*

        $(
            implfrom! { $attr Register<$su> => Register<$tu> }
            implfrom! { $attr Register<$tu> => Register<$su> }
            implfrom! { $attr Register<$ss> => Register<$ts> }
            implfrom! { $attr Register<$ts> => Register<$ss> }
            implfrom! { $attr Register<$su> => Register<$ts> }
            implfrom! { $attr Register<$ts> => Register<$su> }
            implfrom! { $attr Register<$ss> => Register<$tu> }
            implfrom! { $attr Register<$tu> => Register<$ss> }

            implfrom! { $attr $su => Register<$tu> }
            implfrom! { $attr $tu => Register<$su> }
            implfrom! { $attr $ss => Register<$ts> }
            implfrom! { $attr $ts => Register<$ss> }
            implfrom! { $attr $su => Register<$ts> }
            implfrom! { $attr $ts => Register<$su> }
            implfrom! { $attr $ss => Register<$tu> }
            implfrom! { $attr $tu => Register<$ss> }

            implfrom! { $attr Register<$su> => $tu }
            implfrom! { $attr Register<$tu> => $su }
            implfrom! { $attr Register<$ss> => $ts }
            implfrom! { $attr Register<$ts> => $ss }
            implfrom! { $attr Register<$su> => $ts }
            implfrom! { $attr Register<$ts> => $su }
            implfrom! { $attr Register<$ss> => $tu }
            implfrom! { $attr Register<$tu> => $ss }
        )?

        implfrom! { $($next)* }
    };
}

implfrom! {
    u8:i8       [u16:i16 u32:i32 u64:i64 u128:i128 usize:isize],
    u16:i16     [u32:i32 u64:i64 u128:i128 usize:isize],

    #[cfg(target_pointer_width = "64")]
    u32:i32     [u64:i64 u128:i128 usize:isize],

    #[cfg(target_pointer_width = "32")]
    u32:i32     [u64:i64 u128:i128] usize:isize,

    u64:i64     [u128:i128],
    u128:i128   [],

    #[cfg(target_pointer_width = "64")]
    usize:isize [u128:i128] u64:i64,

    #[cfg(target_pointer_width = "32")]
    usize:isize [u64:i64 u128:i128] u32:i32,
}

macro_rules! implptr {
    () => {};

    ($($(#[$attr:meta])? $t:ident),* $(,)?) => {
        $(
            $(#[$attr])?
            impl<T: Sized> From<Register<$t>> for *mut T {
                #[inline]
                fn from(value: Register<$t>) -> *mut T {
                    value.0 as _
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<Register<$t>> for *const T {
                #[inline]
                fn from(value: Register<$t>) -> *const T {
                    value.0 as _
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<*mut T> for Register<$t> {
                #[inline]
                fn from(value: *mut T) -> Register<$t> {
                    Self(value as _)
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<*const T> for Register<$t> {
                #[inline]
                fn from(value: *const T) -> Register<$t> {
                    Self(value as _)
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<&mut [T]> for Register<$t> {
                #[inline]
                fn from(value: &mut [T]) -> Register<$t> {
                    Self(value.as_mut_ptr() as $t)
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<&[T]> for Register<$t> {
                #[inline]
                fn from(value: &[T]) -> Register<$t> {
                    Self(value.as_ptr() as $t)
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<&mut T> for Register<$t> {
                #[inline]
                fn from(value: &mut T) -> Register<$t> {
                    Self(value as *mut T as $t)
                }
            }

            $(#[$attr])?
            impl<T: Sized> From<&T> for Register<$t> {
                #[inline]
                fn from(value: &T) -> Register<$t> {
                    Self(value as *const T as $t)
                }
            }
        )*
    };
}

implptr! {
    usize,

    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
    u64,

    #[cfg(target_pointer_width = "32")]
    u32,
}

/// A register
///
/// This type is intended to be used wherever raw access to a register value
/// is required. The type itself is opaque, but it can be converted to usable
/// types.
///
/// One important additional feature is that registers can be converted between
/// underlying types so long as the conversion does not truncate. For example,
/// `Register<u64>` can be converted to `Register<usize>` on 64-bit systems.
/// Likewise, `Register<usize>` can be converted to and from a pointer.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct Register<T>(T);

impl<T> Register<T> {
    /// Converts a register value to a slice
    ///
    /// # Safety
    ///
    /// This function is unsafe because we are converting an integer to a
    /// pointer and then dereferencing it. The caller MUST ensure that
    /// the value of this register points to valid memory.
    #[inline]
    pub unsafe fn as_slice<'a, U>(self, len: usize) -> &'a [U]
    where
        Self: Into<*const U>,
    {
        core::slice::from_raw_parts(self.into(), len)
    }

    /// Converts a register value to a mutable slice
    ///
    /// # Safety
    ///
    /// This function is unsafe because we are converting an integer to a
    /// pointer and then dereferencing it. The caller MUST ensure that
    /// the value of this register is valid memory.
    #[inline]
    pub unsafe fn as_slice_mut<'a, U>(self, len: usize) -> &'a mut [U]
    where
        Self: Into<*mut U>,
    {
        core::slice::from_raw_parts_mut(self.into(), len)
    }
}

#[cfg(test)]
mod tests {
    use super::Register;

    #[test]
    fn integers() {
        Register::<usize>::from(0u8);
        Register::<usize>::from(0u16);
        Register::<usize>::from(0u32);
        Register::<usize>::from(0i8);
        Register::<usize>::from(0i16);
        Register::<usize>::from(0i32);

        Register::<u64>::from(0usize);
        Register::<u64>::from(0isize);
    }

    #[test]
    fn pointers() {
        <*const u8>::from(Register::<usize>::from(0));
        Register::<usize>::from(&0u8);
        Register::<usize>::from(&0u8 as *const u8);

        <*mut u8>::from(Register::<usize>::from(0));
        Register::<usize>::from(&mut 0u8);
        Register::<usize>::from(&mut 0u8 as *mut u8);
    }

    #[test]
    fn slice() {
        let mut buf = [7u8, 5, 3, 9, 4, 7, 2, 6];

        let reg = Register::<usize>::from(&buf[..]);
        let slc: &[u8] = unsafe { reg.as_slice(8) };
        assert_eq!(slc[2], buf[2]);

        let reg = Register::<usize>::from(&mut buf[..]);
        let slc: &mut [u8] = unsafe { reg.as_slice_mut(8) };
        assert_eq!(slc[3], buf[3]);

        slc[3] = 0;
        assert_eq!(buf[3], 0);
    }
}
