// SPDX-License-Identifier: Apache-2.0

//! Secrets page

use crate::spin::{Locked, RacyCell};

use spin::Lazy;

/// The SEV-SNP secrets page OS area
///
/// The secrets page contains 96-bytes of reserved field that can be used by
/// the guest OS. The guest OS uses the area to save the message sequence
/// number for each VMPL level.
///
/// See the GHCB spec section Secret page layout for the format for this area.
#[repr(C)]
#[derive(Debug)]
pub struct SecretsOsArea {
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 0
    pub msg_seqno_0: u32,
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 1
    pub msg_seqno_1: u32,
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 2
    pub msg_seqno_2: u32,
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 3
    pub msg_seqno_3: u32,
    /// AP jump table in physical addresses
    pub ap_jump_table_pa: u64,
    rsvd: [u8; 40],
    /// Free for guest usage
    pub guest_usage: [u8; 32],
}

/// Virtual Machine Private Communication Key Length
pub const VMPCK_KEY_LEN: usize = 32;

/// The SEV-SNP secrets page
///
/// See the SNP spec secrets page layout section for the structure
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct SnpSecretsPage {
    /// Version
    pub version: u32,
    /// Indicates that an IMI is used to migrate the guest
    pub imi_en: u32,
    /// Family, model, and stepping information as reported in CPUID Fn0000_0001_EAX
    pub fms: u32,
    reserved2: u32,
    /// Guest OS visible workarounds as provided by the HV in SNP_LAUNCH_START
    pub gosvw: [u8; 16],
    /// Virtual Machine Private Communication Key for VMPL 0
    pub vmpck0: [u8; VMPCK_KEY_LEN],
    /// Virtual Machine Private Communication Key for VMPL 1
    pub vmpck1: [u8; VMPCK_KEY_LEN],
    /// Virtual Machine Private Communication Key for VMPL 2
    pub vmpck2: [u8; VMPCK_KEY_LEN],
    /// Virtual Machine Private Communication Key for VMPL 3
    pub vmpck3: [u8; VMPCK_KEY_LEN],
    /// Area mutable for the Guest OS
    pub os_area: SecretsOsArea,
    reserved3: [u8; 3840],
}

/// A handle to the Secrets page
pub struct SecretsHandle<'a> {
    secrets: &'a mut SnpSecretsPage,
}

/// The global Enarx SECRETS
///
/// # Safety
///
/// `SECRETS` is the only way to get an instance of the static `_ENARX_SECRETS` struct.
/// It is guarded by `RwLocked`.
pub static SECRETS: Lazy<Locked<SecretsHandle<'_>>> = Lazy::new(|| {
    extern "C" {
        /// Extern
        pub static _ENARX_SECRETS: RacyCell<SnpSecretsPage>;
    }
    unsafe {
        let secrets = _ENARX_SECRETS.get();
        Locked::<SecretsHandle<'_>>::new(SecretsHandle {
            secrets: &mut *secrets,
        })
    }
});

impl Locked<SecretsHandle<'_>> {
    /// get VM private communication key for VMPL0
    pub fn get_vmpck0(&self) -> [u8; VMPCK_KEY_LEN] {
        let this = self.lock();
        this.secrets.vmpck0
    }

    /// get message sequence number for VM private communication key for VMPL0
    pub fn get_msg_seqno_0(&self) -> u32 {
        let this = self.lock();
        this.secrets.os_area.msg_seqno_0.checked_add(1).unwrap()
    }

    /// increase message sequence number for VM private communication key for VMPL0
    pub fn inc_msg_seqno_0(&self) {
        let mut this = self.lock();
        this.secrets.os_area.msg_seqno_0 = this.secrets.os_area.msg_seqno_0.checked_add(2).unwrap();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use testaso::testaso;

    testaso! {
        struct SnpSecretsPage: 4096, 4096 => {
            version:    0,
            imi_en:     4,
            fms:        8,
            gosvw:   0x10,
            vmpck0:  0x20,
            vmpck1:  0x40,
            vmpck2:  0x60,
            vmpck3:  0x80,
            os_area: 0xA0
        }

        struct SecretsOsArea: 8, 96 => {
            msg_seqno_0:        0,
            msg_seqno_1:        4,
            msg_seqno_2:        8,
            msg_seqno_3:       12,
            ap_jump_table_pa:  16,
            guest_usage:       64
        }
    }
}
