// SPDX-License-Identifier: Apache-2.0

//! This crate contains functionality to manage and run the WASM workload.

#![deny(missing_docs)]

/// Result type used throughout the library.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod workload;
pub use workload::{Workload, WorkloadReader};

#[cfg(target_os = "linux")]
pub use workload::fd_workload_reader::FdWorkloadReader;
