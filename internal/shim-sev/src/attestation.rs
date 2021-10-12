// SPDX-License-Identifier: Apache-2.0

//! SEV attestation handling

use core::hint::unreachable_unchecked;
use core::mem::MaybeUninit;

use nbytes::bytes;

/// The maximum size of the injected secret for SEV keeps
#[allow(clippy::integer_arithmetic)]
pub const SEV_SECRET_MAX_SIZE: usize = bytes!(16; KiB);

/// A 16 byte aligned SevSecret with unknown content
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
pub struct SevSecret {
    /// the secret byte blob
    pub data: MaybeUninit<[u8; SEV_SECRET_MAX_SIZE]>,
}

impl Default for SevSecret {
    fn default() -> Self {
        Self {
            data: MaybeUninit::uninit(),
        }
    }
}

impl SevSecret {
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
    #[allow(dead_code)]
    pub fn try_len(&self) -> Option<usize> {
        let len = unsafe { SevSecret::cbor_len(self.data.as_ptr() as _) };
        len.filter(|len| *len <= SEV_SECRET_MAX_SIZE)
    }

    /// Get a slice of the secret
    #[allow(dead_code)]
    pub fn try_as_slice(&self) -> Option<&[u8]> {
        self.try_len()
            .map(|len| &unsafe { &*self.data.as_ptr() }[..len])
    }
}
