// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::Personality;
use kvm_ioctls::VmFd;

use super::ioctl::{KvmEncRegion, KvmUserspaceMemoryRegion, ENCRYPT_REGION};

pub struct Sev;

impl Personality for Sev {
    fn add_memory(vm: &mut VmFd, region: &KvmUserspaceMemoryRegion) {
        let enc_region = KvmEncRegion::new(region);
        ENCRYPT_REGION
            .ioctl(vm, &enc_region)
            .map(|_| ())
            .expect("SEV memory pinning failed");
    }
}
