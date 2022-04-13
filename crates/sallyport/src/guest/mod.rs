// SPDX-License-Identifier: Apache-2.0

//! Guest entrypoint into the sallyport.
//!
//! The main entrypoint into this module is a long-lived [`Handler`], which allocates the requests
//! within the untrusted sallyport block, passes control to the host for execution of the block via
//! [`sally`](Handler::sally) and reads the replies once it gets the control
//! back after verifying the integrity of the block.
//!
//! In case the [`Handler`] detects that integrity of the request block is not maintained, it
//! attempts to [`exit`](`Handler::exit`) immediately and does so in an infinite loop.
//!
//! [`Handler`] provides:
//! - API for execution of an arbitrary [`Call`]:
//!     - [`execute`](Handler::execute)
//!
//! - [`libc`]-like API for syscall execution using safe Rust abstractions where possible, for example:
//!     - [`syscall`](Handler::syscall) corresponding to [`libc::syscall`].
//!     - [`read`](Handler::read) corresponding to [`libc::read`].
//!     - [`exit`](Handler::exit) corresponding to [`libc::exit`].
//!
//! # Call lifetime phases
//!
//! The crate identifies 3 distinct phases of an arbitrary call lifetime:
//!
//! ## Stage
//! In this phase [input references], [output references] and [inout references] are sequentially allocated within the untrusted sallyport block.
//!
//! Once this phase is finished, no more allocations can be made within the untrusted sallyport block.
//!
//! ## Commit
//! In this phase data is written to [input references] and [inout references] allocated in the stage phase.
//! This may happen concurrently for `N` staged requests.
//!
//! Once this phase is finished, the untrusted sallyport block is ready to be passed to the host for execution
//! via [`sally`](Handler::sally).
//!
//! Entities that can be committed implement the [`Commit`](alloc::Commit) trait.
//!
//! ## Collect
//! In this phase data is read from [output references] and [inout references] allocated in the stage phase.
//! This may happen concurrently for `N` staged requests.
//!
//! This phase starts after the control returns to the guest.
//! Once this phase is finished, the data within block is considered to be invalid, it may be left unchanged,
//! but it may also be overwritten or dropped depending on request implementation
//!
//! Entities that can be collected implement the [`Collect`](alloc::Collect) trait.
//!
//! [inout references]: alloc::InOutRef
//! [input references]: alloc::InRef
//! [output references]: alloc::OutRef

#[allow(clippy::len_without_is_empty)]
pub mod alloc;
pub mod call;

mod handler;
mod platform;
mod tls;

pub use call::{enarxcall, gdbcall, syscall, Call};
pub use handler::*;
pub use platform::*;
pub use tls::*;
