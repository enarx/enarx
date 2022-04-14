// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), no_std)]
#![deny(clippy::all)]
// TODO: Enable https://github.com/enarx/sallyport/issues/32
//#![deny(missing_docs)]
#![feature(core_ffi_c)]
#![feature(c_size_t)]
#![feature(nonnull_slice_from_raw_parts)]
#![feature(slice_ptr_len)]

pub mod elf;
pub mod guest;
pub mod host;
pub mod item;
pub mod libc;
pub mod util;

/// Error type used within this crate.
pub type Error = core::ffi::c_int;

/// Result type returned by functionality exposed by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Internal representation of a null pointer or [`Option::None`] value in the sallyport block.
pub const NULL: usize = usize::MAX;

/// The sallyport version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The sallyport version requires
///
/// This value provides a semver version requirement. It insists that the
/// other side must use a compatible release to this one. For example, if
/// the `VERSION` of sallyport is 1.2.3, `REQUIRES` will contain `^1.2.3`.
///
/// See [this link](https://docs.rs/semver/1.0.0/semver/enum.Op.html#opcaretcompatible-updates)
/// for more details.
pub const REQUIRES: [u8; VERSION.len() + 1] = {
    let mut value = [0u8; VERSION.len() + 1];
    let mut i = 0;

    value[0] = b'^';
    while i < VERSION.len() {
        value[i + 1] = VERSION.as_bytes()[i];
        i += 1;
    }

    value
};

/// I/O port used to trigger an exit to the host (`#VMEXIT`) for KVM driven shims.
pub const KVM_SYSCALL_TRIGGER_PORT: u16 = 0xFF;
