// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::os::unix::io::AsRawFd;

use super::ioctl::{KvmEncRegion, KvmUserspaceMemoryRegion, ENCRYPT_REGION};

pub fn mark_encrypted(kvm_fd: &impl AsRawFd, region: &KvmUserspaceMemoryRegion) -> Result<()> {
    let enc_region = KvmEncRegion::new(region);
    ENCRYPT_REGION
        .ioctl(&mut kvm_fd.as_raw_fd(), &enc_region)
        .map(|_| ())
}
