// SPDX-License-Identifier: Apache-2.0

//! SEV attestation handling

use crate::hostlib::{BootInfo, SevSecret, SEV_SECRET_MAX_SIZE};
use crate::C_BIT_MASK;
use core::hint::unreachable_unchecked;
use core::sync::atomic::Ordering;
use spinning::RwLock;

/// A copy of the injected SEV secret.
#[derive(Copy, Clone, Debug)]
pub struct SevSecretCopy {
    /// the secret byte blob
    data: [u8; SEV_SECRET_MAX_SIZE],
}

/// The secret injected by the Hypervisor
pub static SEV_SECRET: RwLock<SevSecretCopy> = RwLock::<SevSecretCopy>::const_new(
    spinning::RawRwLock::const_new(),
    SevSecretCopy {
        data: [0u8; SEV_SECRET_MAX_SIZE],
    },
);

impl SevSecretCopy {
    #[allow(clippy::integer_arithmetic)]
    unsafe fn cbor_len(data: *const u8) -> Option<usize> {
        let prefix = data.read();

        // only accept CBOR BYTES type
        if (prefix >> 5) != 2 {
            return None;
        }

        // mask the minor
        match prefix & 0b00011111 {
            x @ 0..=23 => Some(1 + x as usize),
            24 => Some(1 + 1 + data.add(1).read() as usize),
            25 => {
                let data = data.add(1) as *const [u8; 2];
                Some(1 + 2 + u16::from_be_bytes(data.read()) as usize)
            }
            26 => {
                let data = data.add(1) as *const [u8; 4];
                Some(1 + 4 + u32::from_be_bytes(data.read()) as usize)
            }
            27 => {
                let data = data.add(1) as *const [u8; 8];
                Some(1 + 8 + u64::from_be_bytes(data.read()) as usize)
            }
            28 => None,
            29 => None,
            30 => None,
            31 => None,
            32..=255 => unreachable_unchecked(),
        }
    }

    /// get the length of the secret
    pub fn try_len(&self) -> Option<usize> {
        unsafe { SevSecretCopy::cbor_len(self.data.as_ptr()) }
    }

    /// Backup the secret injected by the Hypervisor
    ///
    /// # Safety
    /// The caller has to ensure `boot_info` is pointing
    /// to the initial BootInfo passed by the Hypervisor.
    pub unsafe fn copy_from_bootinfo(&mut self, boot_info: *const BootInfo) {
        if C_BIT_MASK.load(Ordering::Relaxed) == 0 {
            return;
        }

        let secret_ptr = SevSecret::get_secret_ptr(boot_info);

        let secret_len = match SevSecretCopy::cbor_len(secret_ptr as *const u8) {
            None => return,
            Some(len) => len,
        };

        if secret_len > SEV_SECRET_MAX_SIZE {
            return;
        }

        core::ptr::copy_nonoverlapping::<u8>(
            (*secret_ptr).data.as_ptr() as _,
            self.data.as_mut_ptr(),
            secret_len,
        );
    }

    /// Get a slice of the secret
    pub fn try_as_slice(&self) -> Option<&[u8]> {
        self.try_len().map(|len| &self.data[..len])
    }
}
