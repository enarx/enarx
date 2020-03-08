// SPDX-License-Identifier: Apache-2.0

//! An enumeration type with a known size and defined unknown variant behaviors
//!
//! Rust `enum`s are great. But they don't have a defined size. You can sort
//! of work around this with `#[repr(type)]`, but this doesn't work with type
//! aliases. Further, you can't use native enums with things like hardware
//! because if an unknown variant appears, all sorts of behavior is undefined.
//!
//! This crate provides a macro (`enumerate!`) which allows you to create
//! Rust-style enumerations as a newtype with a defined size. This also allows
//! defined conversions between the integer type. It also enforces
//! non-exhaustive matching semantics even within the same crate.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

/// Creates an enum-like newtype with defined unknown variant behaviors.
///
/// The syntax is almost identical to standard `enum`s, except the added size:
///
/// ```rust
///
/// use enumerate::enumerate;
///
/// enumerate! {
///     pub enum Foo: u8 {
///         Bar = 0,
///         Baz = 1,
///     }
/// }
///
/// assert_eq!("Bar", format!("{:?}", Foo::Bar));
/// assert_eq!("Unknown(128)", format!("{:?}", Foo::from(128)));
/// ```
#[macro_export]
macro_rules! enumerate {
    (
        $(
            $(#[$attrs:meta])*
            $vis:vis enum $name:ident: $t:ty {
                $(
                    $(#[$vattr:meta])*
                    $var:ident = $val:expr
                ),* $(,)*
            }
        )*
    ) => {
        $(
            $(#[$attrs])*
            #[repr(transparent)]
            #[derive(PartialEq, Eq)]
            $vis struct $name($t);

            impl $crate::Enum for $name {
                const ALL: &'static [Self] = &[$(Self::$var),*];
            }

            impl core::fmt::Debug for $name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    match *self {
                        $(Self::$var => write!(f, "{}", stringify!($var)),)*
                        _ => write!(f, "Unknown({})", self.0)
                    }
                }
            }

            impl From<$t> for $name {
                fn from(value: $t) -> Self {
                    Self(value)
                }
            }

            impl From<$name> for $t {
                fn from(value: $name) -> Self {
                    value.0
                }
            }

            #[allow(non_upper_case_globals)]
            impl $name {
                $(
                    $(#[$vattr])*
                    pub const $var: Self = Self($val);
                )*
            }
        )*
    };
}

/// A trait implemented for all enumerations
pub trait Enum: 'static + Sized {
    /// The set of all known enumeration variants
    const ALL: &'static [Self];
}

#[cfg(test)]
mod tests {
    mod vis {
        enumerate! {
            pub(crate) enum Foo: u8 {}
            pub(super) enum Bar: u8 {}
            enum Baz: u8 {}
        }
    }

    #[test]
    pub fn size() {
        use std::mem::size_of;

        enumerate! {
            enum Foo: u8 {}
            enum Bar: u16 {}
            enum Baz: u32 {}
            enum Qux: u64 {}
        }

        assert_eq!(size_of::<u8>(), size_of::<Foo>());
        assert_eq!(size_of::<u16>(), size_of::<Bar>());
        assert_eq!(size_of::<u32>(), size_of::<Baz>());
        assert_eq!(size_of::<u64>(), size_of::<Qux>());
    }

    #[test]
    pub fn align() {
        use std::mem::align_of;

        enumerate! {
            enum Foo: u8 {}
            enum Bar: u16 {}
            enum Baz: u32 {}
            enum Qux: u64 {}
        }

        assert_eq!(align_of::<u8>(), align_of::<Foo>());
        assert_eq!(align_of::<u16>(), align_of::<Bar>());
        assert_eq!(align_of::<u32>(), align_of::<Baz>());
        assert_eq!(align_of::<u64>(), align_of::<Qux>());
    }

    #[test]
    pub fn debug() {
        mod old {
            #[derive(Debug)]
            pub enum Foo {
                Bar = 0,
                Baz = 1,
            }
        }

        mod new {
            enumerate! {
                pub enum Foo: u8 {
                    Bar = 0,
                    Baz = 1
                }
            }
        }

        assert_eq!(
            format!("{:?}", old::Foo::Bar),
            format!("{:?}", new::Foo::Bar)
        );
        assert_eq!(
            format!("{:?}", old::Foo::Baz),
            format!("{:?}", new::Foo::Baz)
        );
        assert_eq!("Unknown(255)", format!("{:?}", new::Foo::from(255)));
        assert_eq!("Unknown(128)", format!("{:?}", new::Foo::from(128)));
    }

    #[test]
    pub fn matched() {
        use super::Enum;

        enumerate! {
            enum Foo: u8 {
                Bar = 0,
                Baz = 1
            }
        }

        let rnd = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match Foo::ALL[rnd as usize % Foo::ALL.len()] {
            Foo::Bar => eprintln!("Bar"),
            Foo::Baz => eprintln!("Baz"),
            _ => panic!("Unexpected enum variant!"),
        }
    }
}
