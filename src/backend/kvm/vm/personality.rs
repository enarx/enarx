// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::VmFd;

use super::KvmUserspaceMemoryRegion;

/// The `Personality` trait hooks into events that occur during
/// runtime.
///
/// This allows implementors the ability to respond to certain
/// events as needed.
///
/// If a personality is not needed, pass in Unit.
pub trait Personality {
    fn add_memory(_vm: &VmFd, _region: &KvmUserspaceMemoryRegion) {}
}

impl Personality for () {}
