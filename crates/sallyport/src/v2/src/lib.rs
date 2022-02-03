// SPDX-License-Identifier: Apache-2.0

//! API for the hypervisor-microkernel boundary
//!
//! `sallyport` is a protocol crate for proxying service requests (such as syscalls) from an Enarx Keep
//! to the host. A [sally port](https://en.wikipedia.org/wiki/Sally_port) is a secure gateway through
//! which a defending army might "sally forth" from the protection of their fortification.
//!
//! # Mechanism of action
//!
//! `sallyport` works by providing the host with the most minimal register context it requires to
//! perform the syscall on the Keep's behalf. In doing so, the host can immediately call the desired
//! syscall without any additional logic required.
//!
//! Guest and host side communicate via a mutually-distrusted shared block of memory.
//!
//! This crate provides functionality for the guest to execute arbitary requests by proxying requests to the host via
//! the untrusted block and corresponding functionality for the host to execute the requests contained within the untrusted block.
//!
//! # Block format
//!
//! The sallyport [block](item::Block) is a region of memory containing zero or more [items](item::Item).
//! All items contain the following [header](item::Header):
//!
//! * size: `usize`
//! * kind: `usize`
//!
//! The size parameter includes the full length of the item except the header value. The contents of the item are defined by the value of the [`kind`](item::Kind) parameter. An item with an unknown [`kind`](item::Kind) can be skipped since the length of the item is known from the `size` field. The recipient of an item with an unknown [`kind`](item::Kind) MUST NOT try to interpret or modify the contents of the item in any way.
//!
//! ## Kinds
//!
//! * `END`: `0`
//! * `SYSCALL`: `1`
//! * ...
//!
//! ### End
//!
//! An [`END`](item::Kind::End) item MUST have a `size` of `0`. It has no contents and simply marks the end of items in the block. This communicates the end of the items list to the host. However, the guest MUST NOT rely on the presence of a terminator upon return to the guest.
//!
//! ### Syscall
//!
//! A `SYSCALL` item has the following contents:
//!
//! * `nmbr`: `usize` - the syscall number
//! * `arg0`: `usize` - the first argument
//! * `arg1`: `usize` - the second argument
//! * `arg2`: `usize` - the third argument
//! * `arg3`: `usize` - the fourth argument
//! * `arg4`: `usize` - the fifth argument
//! * `arg5`: `usize` - the sixth argument
//! * `ret0`: `usize` - the first return value
//! * `ret1`: `usize` - the second return value
//! * `data`: `...` - data that can be referenced (optional)
//!
//! The argument values may contain numeric values. However, all pointers MUST be translated to an offset from the beginning of the data section.

#![feature(nonnull_slice_from_raw_parts)]
#![feature(slice_ptr_len)]
#![cfg_attr(not(test), no_std)]

pub mod guest;
pub mod host;
pub mod item;
pub mod iter;

/// Error type used within this crate.
pub type Error = libc::c_int;

/// Result type returned by functionality exposed by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Internal representation of a null pointer or [`Option::None`] value in the sallyport block.
pub const NULL: usize = usize::MAX;
