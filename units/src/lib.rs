// SPDX-License-Identifier: Apache-2.0

//! Welcome to units!
//!
//! The `units` crate exists to provide compile-time evaluation of various
//! unit conversions. Currently we support conversions of the various suffixes
//! related to bytes. For example:
//!
//! ```rust
//! use units::bytes;
//!
//! assert_eq!(bytes![2; KiB], 2048);
//! assert_eq!(bytes![2; kB], 2000);
//! ```

#![deny(clippy::all)]
#![no_std]
#![deny(missing_docs)]

/// This macro implements byte suffixes using the
/// [JEDEC memory standards](https://en.wikipedia.org/wiki/JEDEC_memory_standards).
#[macro_export]
macro_rules! jedec {
    ($n:expr; KB) => { $n * 1024 };
    ($n:expr; MB) => { $crate::jedec![$n * 1024; KB] };
    ($n:expr; GB) => { $crate::jedec![$n * 1024; MB] };
}

/// This macro implements [SI byte suffixes](https://en.wikipedia.org/wiki/Kilobyte).
#[macro_export]
macro_rules! si {
    ($n:expr; kB) => { $n * 1000 };
    ($n:expr; MB) => { $crate::si![$n * 1000; kB] };
    ($n:expr; GB) => { $crate::si![$n * 1000; MB] };
    ($n:expr; TB) => { $crate::si![$n * 1000; GB] };
    ($n:expr; PB) => { $crate::si![$n * 1000; TB] };
    ($n:expr; EB) => { $crate::si![$n * 1000; PB] };
    ($n:expr; ZB) => { $crate::si![$n * 1000; EB] };
    ($n:expr; YB) => { $crate::si![$n * 1000; ZB] };
}

/// This macro implements [ISO/IEC 80000 byte suffixs](https://en.wikipedia.org/wiki/ISO/IEC_80000).
#[macro_export]
macro_rules! iec {
    ($n:expr; KiB) => { $n * 1024 };
    ($n:expr; MiB) => { $crate::iec![$n * 1024; KiB] };
    ($n:expr; GiB) => { $crate::iec![$n * 1024; MiB] };
    ($n:expr; TiB) => { $crate::iec![$n * 1024; GiB] };
    ($n:expr; PiB) => { $crate::iec![$n * 1024; TiB] };
    ($n:expr; EiB) => { $crate::iec![$n * 1024; PiB] };
    ($n:expr; ZiB) => { $crate::iec![$n * 1024; EiB] };
    ($n:expr; YiB) => { $crate::iec![$n * 1024; ZiB] };
}

/// A conveneince wrapper for the dominant byte suffixes.
///
/// Both the JEDEC and ISO/IEC 80000 byte suffixes are supported.
/// For more details, see `si!()` and `iec!()`.
#[macro_export]
macro_rules! bytes {
    ($n:expr; kB) => { $crate::si![$n; kB] };
    ($n:expr; MB) => { $crate::si![$n; MB] };
    ($n:expr; GB) => { $crate::si![$n; GB] };
    ($n:expr; TB) => { $crate::si![$n; TB] };
    ($n:expr; PB) => { $crate::si![$n; PB] };
    ($n:expr; EB) => { $crate::si![$n; EB] };
    ($n:expr; ZB) => { $crate::si![$n; ZB] };
    ($n:expr; YB) => { $crate::si![$n; YB] };

    ($n:expr; KiB) => { $crate::iec![$n; KiB] };
    ($n:expr; MiB) => { $crate::iec![$n; MiB] };
    ($n:expr; GiB) => { $crate::iec![$n; GiB] };
    ($n:expr; TiB) => { $crate::iec![$n; TiB] };
    ($n:expr; PiB) => { $crate::iec![$n; PiB] };
    ($n:expr; EiB) => { $crate::iec![$n; EiB] };
    ($n:expr; ZiB) => { $crate::iec![$n; ZiB] };
    ($n:expr; YiB) => { $crate::iec![$n; YiB] };
}

#[cfg(test)]
mod tests {
    #[test]
    fn jedec() {
        assert_eq!(7, 1024u128.pow(0) * 7);
        assert_eq!(jedec![7; KB], 1024u128.pow(1) * 7);
        assert_eq!(jedec![7; MB], 1024u128.pow(2) * 7);
        assert_eq!(jedec![7; GB], 1024u128.pow(3) * 7);
    }

    #[test]
    fn si() {
        assert_eq!(7, 1000u128.pow(0) * 7);
        assert_eq!(si![7; kB], 1000u128.pow(1) * 7);
        assert_eq!(si![7; MB], 1000u128.pow(2) * 7);
        assert_eq!(si![7; GB], 1000u128.pow(3) * 7);
        assert_eq!(si![7; TB], 1000u128.pow(4) * 7);
        assert_eq!(si![7; PB], 1000u128.pow(5) * 7);
        assert_eq!(si![7; EB], 1000u128.pow(6) * 7);
        assert_eq!(si![7; ZB], 1000u128.pow(7) * 7);
        assert_eq!(si![7; YB], 1000u128.pow(8) * 7);
    }

    #[test]
    fn iec() {
        assert_eq!(7, 1024u128.pow(0) * 7);
        assert_eq!(iec![7; KiB], 1024u128.pow(1) * 7);
        assert_eq!(iec![7; MiB], 1024u128.pow(2) * 7);
        assert_eq!(iec![7; GiB], 1024u128.pow(3) * 7);
        assert_eq!(iec![7; TiB], 1024u128.pow(4) * 7);
        assert_eq!(iec![7; PiB], 1024u128.pow(5) * 7);
        assert_eq!(iec![7; EiB], 1024u128.pow(6) * 7);
        assert_eq!(iec![7; ZiB], 1024u128.pow(7) * 7);
        assert_eq!(iec![7; YiB], 1024u128.pow(8) * 7);
    }

    #[test]
    fn bytes() {
        assert_eq!(7, 1000u128.pow(0) * 7);
        assert_eq!(bytes![7; kB], 1000u128.pow(1) * 7);
        assert_eq!(bytes![7; MB], 1000u128.pow(2) * 7);
        assert_eq!(bytes![7; GB], 1000u128.pow(3) * 7);
        assert_eq!(bytes![7; TB], 1000u128.pow(4) * 7);
        assert_eq!(bytes![7; PB], 1000u128.pow(5) * 7);
        assert_eq!(bytes![7; EB], 1000u128.pow(6) * 7);
        assert_eq!(bytes![7; ZB], 1000u128.pow(7) * 7);
        assert_eq!(bytes![7; YB], 1000u128.pow(8) * 7);

        assert_eq!(7, 1024u128.pow(0) * 7);
        assert_eq!(bytes![7; KiB], 1024u128.pow(1) * 7);
        assert_eq!(bytes![7; MiB], 1024u128.pow(2) * 7);
        assert_eq!(bytes![7; GiB], 1024u128.pow(3) * 7);
        assert_eq!(bytes![7; TiB], 1024u128.pow(4) * 7);
        assert_eq!(bytes![7; PiB], 1024u128.pow(5) * 7);
        assert_eq!(bytes![7; EiB], 1024u128.pow(6) * 7);
        assert_eq!(bytes![7; ZiB], 1024u128.pow(7) * 7);
        assert_eq!(bytes![7; YiB], 1024u128.pow(8) * 7);
    }
}
