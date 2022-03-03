// SPDX-License-Identifier: Apache-2.0

//! Types for interacting with the KVM SEV-SNP guest management API.
//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

use super::super::{Error, Indeterminate};
use super::{Finish, Start, Update};

use iocuddle::{Group, Ioctl, WriteRead};
use std::marker::PhantomData;
use std::os::raw::c_ulong;
use std::os::unix::io::AsRawFd;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    Init = 22,
    LaunchStart<'_> = 23,
    LaunchUpdate<'_> = 24,
    LaunchFinish<'_> = 25,
}

const KVM: Group = Group::new(0xAE);
const ENC_OP: Ioctl<WriteRead, &c_ulong> = unsafe { KVM.write_read(0xBA) };

// Note: the iocuddle::Ioctl::lie() constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the SEV-SNP platform in KVM.
pub const SNP_INIT: Ioctl<WriteRead, &Command<'_, Init>> = unsafe { ENC_OP.lie() };

/// Initialize the flow to launch a guest.
pub const SNP_LAUNCH_START: Ioctl<WriteRead, &Command<'_, LaunchStart<'_>>> =
    unsafe { ENC_OP.lie() };

/// Insert pages into the guest physical address space.
pub const SNP_LAUNCH_UPDATE: Ioctl<WriteRead, &Command<'_, LaunchUpdate<'_>>> =
    unsafe { ENC_OP.lie() };

/// Complete the guest launch flow.
pub const SNP_LAUNCH_FINISH: Ioctl<WriteRead, &Command<'_, LaunchFinish<'_>>> =
    unsafe { ENC_OP.lie() };

/// A generic SEV command
#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    sev_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// create the command from a mutable subcommand
    pub fn from_mut(sev: &'a mut impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// create the command from a subcommand reference
    pub fn from(sev: &'a mut impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// encapsulate a `std::io::Error` in an `Indeterminate<Error>`
    pub fn encapsulate(&self, err: std::io::Error) -> Indeterminate<Error> {
        match self.error {
            0 => Indeterminate::<Error>::from(err),
            _ => Indeterminate::<Error>::from(self.error as u32),
        }
    }
}

/// Initialize the SEV-SNP platform in KVM.
#[derive(Default)]
#[repr(C, packed)]
pub struct Init {
    /// Reserved space, must be always set to 0 when issuing the ioctl.
    flags: u64,
}

/// Initialize the flow to launch a guest.
#[repr(C)]
pub struct LaunchStart<'a> {
    /// Guest policy. See Table 7 of the AMD SEV-SNP Firmware
    /// specification for a description of the guest policy structure.
    policy: u64,

    /// Userspace address of migration agent
    ma_uaddr: u64,

    /// 1 if this guest is associated with a migration agent. Otherwise 0.
    ma_en: u8,

    /// 1 if this launch flow is launching an IMI for the purpose of
    /// guest-assisted migration. Otherwise 0.
    imi_en: u8,

    /// Hypervisor provided value to indicate guest OS visible workarounds.
    /// The format is hypervisor defined.
    gosvw: [u8; 16],

    pad: [u8; 6],

    _phantom: PhantomData<&'a [u8]>,
}

impl From<Start<'_>> for LaunchStart<'_> {
    fn from(start: Start<'_>) -> Self {
        Self {
            policy: start.policy.into(),
            ma_uaddr: if let Some(addr) = start.ma_uaddr {
                addr.as_ptr() as u64
            } else {
                0
            },
            ma_en: if start.ma_uaddr.is_some() { 1 } else { 0 },
            imi_en: start.imi_en as _,
            gosvw: start.gosvw,
            pad: [0u8; 6],
            _phantom: PhantomData,
        }
    }
}

/// Insert pages into the guest physical address space.
#[repr(C)]
pub struct LaunchUpdate<'a> {
    /// guest start frame number.
    start_gfn: u64,

    /// Userspace address of the page needed to be encrypted.
    uaddr: u64,

    /// Length of the page needed to be encrypted:
    /// (end encryption uaddr = uaddr + len).
    len: u32,

    /// Indicates that this page is part of the IMI of the guest.
    imi_page: u8,

    /// Encoded page type. See Table 58 if the SNP Firmware specification.
    page_type: u8,

    /// VMPL permission mask for VMPL3. See Table 59 of the SNP Firmware
    /// specification for the definition of the mask.
    vmpl3_perms: u8,

    /// VMPL permission mask for VMPL2.
    vmpl2_perms: u8,

    /// VMPL permission mask for VMPL1.
    vmpl1_perms: u8,

    _phantom: PhantomData<&'a ()>,
}

impl From<Update<'_>> for LaunchUpdate<'_> {
    fn from(update: Update<'_>) -> Self {
        Self {
            start_gfn: update.start_gfn,
            uaddr: update.uaddr.as_ptr() as _,
            len: update.uaddr.len() as _,
            imi_page: if update.imi_page { 1 } else { 0 },
            page_type: update.page_type as _,
            vmpl3_perms: update.vmpl3_perms.bits(),
            vmpl2_perms: update.vmpl2_perms.bits(),
            vmpl1_perms: update.vmpl1_perms.bits(),
            _phantom: PhantomData,
        }
    }
}

pub const KVM_SEV_SNP_FINISH_DATA_SIZE: usize = 32;

/// Complete the guest launch flow.
#[repr(C)]
pub struct LaunchFinish<'a> {
    /// Userspace address of the ID block. Ignored if ID_BLOCK_EN is 0.
    id_block_uaddr: u64,

    /// Userspace address of the authentication information of the ID block. Ignored if ID_BLOCK_EN is 0.
    id_auth_uaddr: u64,

    /// Indicates that the ID block is present.
    id_block_en: u8,

    /// Indicates that the author key is present in the ID authentication information structure.
    /// Ignored if ID_BLOCK_EN is 0.
    auth_key_en: u8,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this value.
    host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],

    pad: [u8; 6],

    _phantom: PhantomData<&'a [u8]>,
}

impl From<Finish<'_, '_>> for LaunchFinish<'_> {
    fn from(finish: Finish<'_, '_>) -> Self {
        let id_block = if let Some(addr) = finish.id_block {
            addr.as_ptr() as u64
        } else {
            0
        };

        let id_auth = if let Some(addr) = finish.id_auth {
            addr.as_ptr() as u64
        } else {
            0
        };

        Self {
            id_block_uaddr: id_block,
            id_auth_uaddr: id_auth,
            id_block_en: if finish.id_block.is_some() { 1 } else { 0 },
            auth_key_en: if finish.id_auth.is_some() { 1 } else { 0 },
            host_data: finish.host_data,
            pad: [0u8; 6],
            _phantom: PhantomData,
        }
    }
}
