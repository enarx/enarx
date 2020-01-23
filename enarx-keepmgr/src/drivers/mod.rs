// SPDX-License-Identifier: Apache-2.0

//! # Overview
//!
//! The traits contained in this module constitute a state machine for
//! launching and managing a keep across multiple technologies. Launching
//! a keep goes through multiple phases, in this order:
//!
//!   1. Driver
//!
//!   2. Setup
//!     a. Shim Setup
//!     b. Keep Setup
//!
//!   3. Build
//!     a. Shim Build
//!     b. Keep Build
//!
//!   4. Enter
//!
//! # Details
//! ## The Driver Phase
//!
//! First, the keep manager must find an appropriate driver for the system.
//! Then, the keep manager must locate the keep runtime and the driver-supplied
//! shim for use in the next phase. When the keep manager is ready to launch
//! a keep, it uses `Driver::make()` to begin the setup phase.
//!
//! ## The Setup Phase
//!
//! The purpose of the setup phase is to give the driver a view of both the
//! keep runtime and shim before creating the actual keep. This is useful for
//! technologies like SGX where we need to hash and sign the binary before
//! creating the keep.
//!
//! The keep manager will load the driver-supplied shim first, followed by
//! keep runtime. Upon completion, we begin the build phase.
//!
//! ## The Build Phase
//!
//! The purpose of the building phase is to actually create a full keep
//! with all the pages actually loaded. The workflow is similar to the
//! setup phase.
//!
//! The keep manager will load the driver-supplied shim first, followed by
//! keep runtime. Upon completion, we begin the enter phase.
//!
//! ## The Enter Phase
//!
//! The enter phase can be considered the main loop of the application.
//! When the keep manager enters the keep, the keep will run until an event
//! occurs. Upon an event, the keep manager will handle the event, potentially
//! collecting the keep's required data, and re-entering the keep.

pub mod debug;

use crate::access::Access;
use crate::span::Span;

use std::io::Result;
use std::path::Path;

/// All possible keep events
#[allow(non_camel_case_types)]
pub enum Event {
    /// Exit the process with the supplied exit value
    exit(i32),

    /// Get the user identifier of the process
    getuid(Keep<libc::uid_t>),
}

/// A trait for supplying statically-linked pages into the keep
pub trait Loader<T> {
    /// Loads data into keep memory
    fn load(&mut self, src: &[u8], dst: Span<u64>, access: Access) -> Result<()>;

    /// Completes the loading process
    fn done(self: Box<Self>, entry: u64) -> Result<T>;
}

/// A trait containing the function used to enter a keep
pub trait Enterer<T> {
    /// Enter the keep with the provided input until the next event
    fn enter(self: Box<Self>, input: T) -> Result<Event>;
}

/// A driver for a particular type of keep
pub trait Driver {
    /// The name of this keep driver
    fn name(&self) -> &str;

    /// The path to the shim for this driver
    fn shim(&self) -> Result<&Path>;

    /// Begin the constructon process for a keep
    fn make(&self) -> Result<ShimSetup>;
}

/// The shim half of the setup phase
pub type ShimSetup = Box<dyn Loader<KeepSetup>>;

/// The keep half of the setup phase
pub type KeepSetup = Box<dyn Loader<ShimBuild>>;

/// The shim half of the build phase
pub type ShimBuild = Box<dyn Loader<KeepBuild>>;

/// The keep half of the build phase
pub type KeepBuild = Box<dyn Loader<Keep<()>>>;

/// A keep which expects the input type `T` in order to resume execution
pub type Keep<T> = Box<dyn Enterer<T>>;
