// SPDX-License-Identifier: Apache-2.0

//! Guest entrypoint into the sallyport.
//!
//! # Phase-based request allocation
//!
//! The crate identifies 3 distinct phases of an arbitrary call lifetime:
//!
//! ## Stage
//! In this phase [input references], [output references] and [inout references] are sequentially allocated within the untrusted sallyport block.
//!
//! Once this phase is finished, no more allocations can be made within the untrusted sallyport block.
//!
//! Entities that can be staged implement the [`Stage`](alloc::Stage) trait.
//!
//! ## Commit
//! In this phase data is written to [input references] and [inout references] allocated in the stage phase.
//! This may happen concurrently for `N` staged requests.
//!
//! Once this phase is finished, the untrusted sallyport block is ready to be passed to the host for execution
//! via [platform-specific `sally`](Platform::sally).
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
#[cfg(test)]
pub mod alloc;
#[cfg(test)]
pub mod syscall;

mod platform;

pub use platform::*;
