// SPDX-License-Identifier: Apache-2.0

// FUTURE: right now we only have one Workldr, `wasmldr`.
// In the future there may be other workload types - in theory we can run
// any static PIE ELF binary. We could have a Lua interpreter, or a
// JavaScript interpreter, or whatever.
// So there's two parts to this trait - call them KeepSetup and Engine.
//
// KeepSetup is the part that actually sets up the Keep for the Workload,
// which might involve setting up network sockets, storage devices, etc.
// This part must be implemented by any Workldr, since we want the
// Enarx environment to be platform-agnostic.
//
// Engine is the (workload-specific) portion that actually interprets or
// executes the workload. It's responsible for taking the sockets / devices
// etc. that were set up by KeepSetup and making them usable in a way that
// the workload will understand.
//
// So: someday we might want to split this into two traits, and we might
// have multiple Workldrs for different languages/environments, and we
// might need to examine the workload and determine which Workldr is
// the right one to use. But first... we gotta make wasmldr work.

#[cfg(feature = "wasmldr")]
pub mod wasmldr;

/// A trait for the "Workloader" - shortened to Workldr, also known as "exec"
/// (as in Backend::keep(shim, exec) [q.v.]) and formerly known as the "code"
/// layer. This is the part that runs inside the keep, prepares the workload
/// environment, and then actually executes the tenant's workload.
///
/// Basically, this is a generic view of wasmldr.
pub trait Workldr {
    /// The name of the Workldr
    fn name(&self) -> &'static str;

    /// The builtin Workldr binary (e.g. wasmldr)
    fn exec(&self) -> &'static [u8];
}
