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
            impl<T: Sized> From<*mut T> for Register<$t> {
                #[inline]
                fn from(value: *mut T) -> Register<$t> {
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
            impl<T: Sized> From<&mut T> for Register<$t> {
                #[inline]
                fn from(value: &mut T) -> Register<$t> {
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
    /// Create a `Register` value from the raw contents
    pub fn from_raw(value: T) -> Self {
        Self(value)
    }

    /// Returns the raw value
    pub fn raw(self) -> T {
        self.0
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
        Register::<usize>::from(&mut 0u8);
        Register::<usize>::from(&mut [0u8; 32]);
        Register::<usize>::from(&mut 0u8 as *mut u8);
    }
}
