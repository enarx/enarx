// SPDX-License-Identifier: Apache-2.0

use core::arch::asm;
use core::mem::MaybeUninit;

use sgx::enclu::EGETKEY;

/// SGX derived key length in bytes
pub const SGX_KEY_LEN: usize = 16;

/// SGX ENCLU[EGETKEY] response
///
/// has to be aligned to 16 bytes as per Intel CPU spec
#[repr(C, align(16))]
pub struct Response {
    pub key: [u8; SGX_KEY_LEN],
}

/// SGX ENCLU[EGETKEY] request
///
/// has to be aligned to 512 bytes as per Intel CPU spec
#[repr(C, align(512))]
pub struct Request {
    pub name: Names,
    pub policy: Policy,
    pub isvsvn: u16,
    pub cet_attr_mask: u8,
    pub rsvd: u8,
    pub cpusvn: [u8; 16],
    pub attribute_mask: [u8; 16],
    pub keyid: [u8; 32],
    pub misc_mask: [u8; 4],
    pub config_svn: u16,
    pub rsvd2: [u8; 434],
}

impl Default for Request {
    fn default() -> Self {
        Self {
            name: Names::EinittokenKey,
            policy: Policy::MRSIGNER,
            isvsvn: 0,
            cet_attr_mask: 0,
            rsvd: 0,
            cpusvn: [0; 16],
            attribute_mask: [0; 16],
            keyid: [0; 32],
            misc_mask: [0; 4],
            config_svn: 0,
            rsvd2: [0; 434],
        }
    }
}

#[allow(dead_code)]
#[repr(u16)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Names {
    /// EINIT_TOKEN key
    EinittokenKey = 0,
    /// Provisioning Key
    ProvisionKey = 1,
    /// Provisioning Seal Key
    ProvisionSealKey = 2,
    /// Report Key
    ReportKey = 3,
    /// Seal Key
    SealKey = 4,
}

bitflags::bitflags! {
    pub struct Policy: u16 {
        const MRENCLAVE = 1 << 0;
        const MRSIGNER = 1 << 1;
        const NOISVPRODID = 1 << 2;
        const CONFIGID = 1 << 3;
        const ISVFAMILYID = 1 << 4;
        const ISVEXTPRODID = 1 << 5;
    }
}

impl Request {
    /// Call SGX ENCLU[EGETKEY]
    ///
    /// This function calls `enclu` with
    /// RAX: EGETKEY
    /// RBX: pointer to request (self)
    /// RCX: pointer to response
    ///
    /// Return value in RAX
    /// 0: success
    /// else: error number (not abstracted here, because not used in error reporting)
    ///
    /// TODO: detailed error reporting
    #[inline]
    pub fn enclu_egetkey(&self) -> Result<Response, u64> {
        // Purposely make an uninitialized memory block for the struct, as it
        // will be initialized by the CPU as the next step.
        let mut key_response = MaybeUninit::<Response>::uninit();

        let mut rax: u64 = EGETKEY as _;

        // In Rust inline assembly rbx is not preserved by the compiler, even
        // when part of the input list. It is one of the callee saved registers
        // dictated by:
        //
        // https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf
        unsafe {
            asm!(
            "xchg       {RBX}, rbx",
            "enclu",
            "mov        rbx, {RBX}",

            RBX = inout(reg) self => _,
            inout("rax") rax,
            in("rcx") key_response.as_mut_ptr(),
            );
        }

        match rax {
            0 => Ok(unsafe { key_response.assume_init() }),
            _ => Err(rax),
        }
    }
}
