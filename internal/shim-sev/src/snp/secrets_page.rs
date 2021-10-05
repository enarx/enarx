// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Secrets page

use crate::spin::RwLocked;
use crate::_ENARX_SECRETS;
use spinning::Lazy;

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
    /// FIXME
    pub msg_seqno_0: u32,
    /// FIXME
    pub msg_seqno_1: u32,
    /// FIXME
    pub msg_seqno_2: u32,
    /// FIXME
    pub msg_seqno_3: u32,
    /// FIXME
    pub ap_jump_table_pa: u64,
    rsvd: [u8; 40],
    /// FIXME
    pub guest_usage: [u8; 32],
}

/// FIXME
pub const VMPCK_KEY_LEN: usize = 32;

/// The SEV-SNP secrets page
///
/// See the SNP spec secrets page layout section for the structure
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct SnpSecretsPage {
    /// FIXME
    pub version: u32,
    /// FIXME
    pub imi_en: u32,
    /// FIXME
    pub fms: u32,
    reserved2: u32,
    /// FIXME
    pub gosvw: [u8; 16],
    /// FIXME
    pub vmpck0: [u8; VMPCK_KEY_LEN],
    /// FIXME
    pub vmpck1: [u8; VMPCK_KEY_LEN],
    /// FIXME
    pub vmpck2: [u8; VMPCK_KEY_LEN],
    /// FIXME
    pub vmpck3: [u8; VMPCK_KEY_LEN],
    /// FIXME
    pub os_area: SecretsOsArea,
    reserved3: [u8; 3840],
}

/// A handle to the Secrets page
pub struct SecretsHandle {
    secrets: &'static mut SnpSecretsPage,
}

/// The global Enarx GHCB
pub static SECRETS: Lazy<RwLocked<SecretsHandle>> = Lazy::new(|| {
    let secrets = unsafe { &mut _ENARX_SECRETS };

    RwLocked::<SecretsHandle>::new(SecretsHandle { secrets })
});

impl RwLocked<SecretsHandle> {
    /// FIXME
    pub fn get_vmpck0(&self) -> [u8; VMPCK_KEY_LEN] {
        let this = self.read();
        this.secrets.vmpck0
    }

    /// FIXME
    pub fn get_msg_seqno_0(&self) -> u32 {
        let this = self.read();
        this.secrets.os_area.msg_seqno_0.checked_add(1).unwrap()
    }

    /// FIXME
    pub fn inc_msg_seqno_0(&self) {
        let mut this = self.write();
        this.secrets.os_area.msg_seqno_0 = this.secrets.os_area.msg_seqno_0.checked_add(2).unwrap();
    }
}
