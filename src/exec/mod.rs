// SPDX-License-Identifier: Apache-2.0

// FUTURE: right now we only have one exec, `enarx-exec-wasmtime`.
// In the future there may be other workload types - in theory we can run
// any static PIE ELF binary. We could have a Lua interpreter, or a
// JavaScript interpreter, or whatever.
// So there's two parts to this trait - call them KeepSetup and Engine.
//
// KeepSetup is the part that actually sets up the Keep for the Workload,
// which might involve setting up network sockets, storage devices, etc.
// This part must be implemented by any Exec, since we want the
// Enarx environment to be platform-agnostic.
//
// Engine is the (exec-specific) portion that actually interprets or
// executes the workload. It's responsible for taking the sockets / devices
// etc. that were set up by KeepSetup and making them usable in a way that
// the workload will understand.
//
// So: someday we might want to split this into two traits, and we might
// have multiple Execs for different languages/environments, and we
// might need to examine the workload and determine which Exec is
// the right one to use. But first... we gotta make exec-wasmtime work.

#[cfg(any(
    feature = "backend-sgx",
    feature = "backend-sev",
    feature = "backend-kvm"
))]
pub mod exec_wasmtime;

use crate::Backend;

use once_cell::sync::Lazy;

/// A trait for the "Exec"
///
/// (as in Backend::keep(shim, exec) [q.v.]) and formerly known as the "code"
/// layer. This is the part that runs inside the keep, prepares the workload
/// environment, and then actually executes the tenant's workload.
///
/// Basically, this is a generic view of exec_wasmtime.
pub trait Exec: Sync + Send {
    /// The name of the executable
    fn name(&self) -> &'static str;

    /// The executable (e.g. exec_wasmtime)
    fn exec(&self) -> &'static [u8];

    /// Picks a suitable executable for the backend
    ///
    /// E.g. in case of the `nil` backend it will pick the `NilExec`,
    /// which calls into the `exec-wasmtime` crate directly, without
    /// loading any binary.
    fn with_backend(&self, backend: &dyn Backend) -> bool;
}

pub struct NilExec;

impl Exec for NilExec {
    fn name(&self) -> &'static str {
        "nil"
    }

    fn exec(&self) -> &'static [u8] {
        &[]
    }

    fn with_backend(&self, backend: &dyn Backend) -> bool {
        backend.name() == "nil"
    }
}

pub static EXECS: Lazy<Vec<Box<dyn Exec>>> = Lazy::new(|| {
    vec![
        #[cfg(any(
            feature = "backend-sgx",
            feature = "backend-sev",
            feature = "backend-kvm"
        ))]
        Box::new(exec_wasmtime::WasmExec),
        #[cfg(feature = "backend-nil")]
        Box::new(NilExec),
    ]
});

#[cfg(test)]
mod test {
    use super::{Exec, NilExec};

    #[test]
    fn coverage() {
        let exec = NilExec;
        assert_eq!(exec.name(), "nil");
        assert!(exec.exec().is_empty());
    }
}
