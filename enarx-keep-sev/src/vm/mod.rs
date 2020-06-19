// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod mem;

pub use builder::Builder;

use mem::Region;

use kvm_ioctls::{Kvm, VmFd};

pub struct VirtualMachine {
    _kvm: Kvm,
    _fd: VmFd,
    address_space: Region,
}
