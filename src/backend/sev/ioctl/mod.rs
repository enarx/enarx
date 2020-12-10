// SPDX-License-Identifier: Apache-2.0

mod types;

use iocuddle::{Group, Ioctl, Read, Write};

pub use types::{KvmEncRegion, KvmUserspaceMemoryRegion};

const KVM: Group = Group::new(0xAE);

/// Instruct the kernel that the supplied memory range is encrypted
/// and therefore the kernel must pin the pages.
///
/// Note: this ioctl's direction is wrong in the kernel headers:
/// _IOR(KVMIO, 0xbb, struct kvm_enc_region), so we will declare
/// it as read and use `iocuddle`'s lie mechanism to represent
/// the correct semantics of the ioctl.
const IOR_ENCRYPT_REGION: Ioctl<Read, &KvmEncRegion> = unsafe { KVM.read(0xBB) };
pub const ENCRYPT_REGION: Ioctl<Write, &KvmEncRegion> = unsafe { IOR_ENCRYPT_REGION.lie() };
