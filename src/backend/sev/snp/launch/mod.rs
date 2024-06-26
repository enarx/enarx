// SPDX-License-Identifier: Apache-2.0

//! An implementation of the SEV-SNP launch process as a type-state machine.
//! This ensures (at compile time) that the right steps are called in the
//! right order.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
use linux::*;

use crate::backend::sev::snp::sign::{PublicKey, Signature};
use crate::backend::ByteSized;

use std::io::Result;
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;

use bitflags::bitflags;
use kvm_ioctls::VmFd;

/// Launcher type-state that indicates a brand new launch.
pub struct New;

/// Launcher type-state that indicates a SNP in-progress.
pub struct Started;

/// Facilitates the correct execution of the SEV launch process.
pub struct Launcher<T, V: AsRawFd> {
    vm_fd: VmFd,
    sev: V,
    state: PhantomData<T>,
}

impl<T, V: AsRawFd> AsRef<VmFd> for Launcher<T, V> {
    /// Give access to the vm fd to create vCPUs or such.
    fn as_ref(&self) -> &VmFd {
        &self.vm_fd
    }
}

impl<T, V: AsRawFd> AsMut<VmFd> for Launcher<T, V> {
    /// Give access to the vm fd to create vCPUs or such.
    fn as_mut(&mut self) -> &mut VmFd {
        &mut self.vm_fd
    }
}

impl<V: AsRawFd> Launcher<New, V> {
    /// Begin the SEV-SNP launch process by creating a Launcher and issuing the
    /// KVM_SEV_INIT2 ioctl.
    pub fn new(vm_fd: VmFd, sev: V) -> Result<Self> {
        let mut launcher = Launcher {
            vm_fd,
            sev,
            state: PhantomData::default(),
        };

        let init = Init2::new();

        let mut cmd = Command::from(&mut launcher.sev, &init);
        SEV_INIT2
            .ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Initialize the flow to launch a guest.
    pub fn start(mut self, start: Start) -> Result<Launcher<Started, V>> {
        let mut launch_start = LaunchStart::from(start);
        let mut cmd = Command::from_mut(&mut self.sev, &mut launch_start);

        SNP_LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let launcher = Launcher {
            vm_fd: self.vm_fd,
            sev: self.sev,
            state: PhantomData::default(),
        };

        Ok(launcher)
    }
}

impl<V: AsRawFd> Launcher<Started, V> {
    /// Encrypt guest SNP data.
    pub fn update_data(&mut self, update: Update<'_>) -> Result<()> {
        let mut launch_update_data = LaunchUpdate::from(update);

        // We may need to issue the ioctl multiple times until the launch
        // updates has been completed.
        while !launch_update_data.is_done() {
            let mut cmd = Command::from_mut(&mut self.sev, &mut launch_update_data);
            SNP_LAUNCH_UPDATE
                .ioctl(&mut self.vm_fd, &mut cmd)
                .map_err(|e| cmd.encapsulate(e))?;
        }

        Ok(())
    }

    /// Complete the SNP launch process.
    pub fn finish(mut self, finish: Finish<'_, '_>) -> Result<(VmFd, V)> {
        let launch_finish = LaunchFinish::from(finish);
        let mut cmd = Command::from(&mut self.sev, &launch_finish);

        SNP_LAUNCH_FINISH
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok((self.vm_fd, self.sev))
    }
}

/// Encapsulates the various data needed to begin the launch process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Start {
    /// Describes a policy that the AMD Secure Processor will enforce.
    pub(crate) policy: u64,

    /// Hypervisor provided value to indicate guest OS visible workarounds.The format is hypervisor defined.
    pub(crate) gosvw: [u8; 16],
}

/// Encapsulates the various data needed to begin the update process.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Update<'a> {
    /// guest start frame number.
    pub(crate) start_gfn: u64,

    /// The userspace of address of the encrypted region.
    pub(crate) uaddr: &'a [u8],

    /// Encoded page type.
    pub(crate) page_type: PageType,
}

impl<'a> Update<'a> {
    /// Encapsulate all data needed for the SNP_LAUNCH_UPDATE ioctl.
    pub fn new(start_gfn: u64, uaddr: &'a [u8], page_type: PageType) -> Self {
        Self {
            start_gfn,
            uaddr,
            page_type,
        }
    }
}

bitflags! {
    #[derive(Default)]
    /// VMPL permission masks.
    pub struct VmplPerms: u8 {
        /// Page is readable by the VMPL.
        const READ = 1;

        /// Page is writeable by the VMPL.
        const WRITE = 1 << 1;

        /// Page is executable by the VMPL in CPL3.
        const EXECUTE_USER = 1 << 2;

        /// Page is executable by the VMPL in CPL2, CPL1, and CPL0.
        const EXECUTE_SUPERVISOR = 1 << 3;
    }
}

/// Encoded page types for a launch update. See Table 58 of the SNP Firmware
/// specification for further details.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub enum PageType {
    /// A normal data page.
    Normal = 0x1,

    /// A VMSA page.
    Vmsa = 0x2,

    /// A page full of zeroes.
    Zero = 0x3,

    /// A page that is encrypted but not measured
    Unmeasured = 0x4,

    /// A page for the firmware to store secrets for the guest.
    Secrets = 0x5,

    /// A page for the hypervisor to provide CPUID function values.
    Cpuid = 0x6,
}

/// Encapsulates the data needed to complete a guest launch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Finish<'a, 'b> {
    /// The userspace address of the authentication information of the ID block and auth.
    pub(crate) id_block_n_auth: Option<(&'a IdBlock, &'b IdAuth)>,

    /// Indicates that the author key is present in the ID authentication information structure.
    pub(crate) auth_key_en: bool,

    pub(crate) vcek_disabled: bool,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this
    /// value.
    pub(crate) host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
}

impl<'a, 'b> Finish<'a, 'b> {
    /// Encapsulate all data needed for the SNP_LAUNCH_FINISH ioctl.
    pub fn new(
        id_block_n_auth: Option<(&'a IdBlock, &'b IdAuth)>,
        auth_key_en: bool,
        vcek_disabled: bool,
        host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
    ) -> Self {
        Self {
            id_block_n_auth,
            auth_key_en,
            vcek_disabled,
            host_data,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IdBlock {
    pub launch_digest: [u8; 48],
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub version: u32, // must be 1 for this ABI
    pub guest_svn: u32,
    pub policy: u64,
}

impl Default for IdBlock {
    fn default() -> Self {
        Self {
            launch_digest: [0u8; 48],
            family_id: [0u8; 16],
            image_id: [0u8; 16],
            version: 1,
            guest_svn: 0,
            policy: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IdAuth {
    pub id_key_algo: u32,
    pub auth_key_algo: u32,
    pub rsvd1: [u8; 56], // must be zero
    pub id_block_sig: Signature,
    pub id_key: PublicKey,
    pub rsvd2: [u8; 60], // must be zero
    pub id_key_sig: Signature,
    pub author_key: PublicKey,
    pub rsvd3: [u8; 892], // must be zero
}

impl Default for IdAuth {
    fn default() -> Self {
        Self {
            id_key_algo: 0,
            auth_key_algo: 0,
            rsvd1: [0u8; 56],
            id_block_sig: Signature::default(),
            id_key: PublicKey::default(),
            rsvd2: [0u8; 60],
            id_key_sig: Signature::default(),
            author_key: PublicKey::default(),
            rsvd3: [0u8; 892],
        }
    }
}

// SAFETY: IdBlock is a C struct with no UD states and pointers.
unsafe impl ByteSized for IdBlock {}

// SAFETY: IdAuth is a C struct with no UD states and pointers.
unsafe impl ByteSized for IdAuth {}

#[derive(Debug)]
#[repr(C)]
pub struct PageInfo {
    pub digest_cur: [u8; 48],
    pub contents: [u8; 48],
    pub length: u16,
    pub page_type: u8,
    pub imi_page: u8,
    pub vmpl3_perms: VmplPerms,
    pub vmpl2_perms: VmplPerms,
    pub vmpl1_perms: VmplPerms,
    pub rsvd: u8,
    pub gpa: u64,
}

impl Default for PageInfo {
    fn default() -> Self {
        Self {
            digest_cur: [0u8; 48],
            contents: [0u8; 48],
            length: size_of::<Self>() as _,
            page_type: 0,
            imi_page: 0,
            vmpl3_perms: VmplPerms::empty(),
            vmpl2_perms: VmplPerms::empty(),
            vmpl1_perms: VmplPerms::empty(),
            rsvd: 0,
            gpa: 0,
        }
    }
}

// SAFETY: PageInfo is a C struct with no UD states and pointers.
unsafe impl ByteSized for PageInfo {}

#[cfg(test)]
mod test {
    use super::*;

    use testaso::testaso;
    testaso! {
        struct IdBlock: 8, 96 => {
            launch_digest: 0,
            family_id: 48,
            image_id: 64,
            version: 80,
            guest_svn: 84,
            policy: 88
        }

        struct IdAuth: 4, 4096 => {
            id_key_algo: 0,
            auth_key_algo: 4,
            rsvd1: 8,
            id_block_sig: 64,
            id_key: 576,
            rsvd2: 1604,
            id_key_sig: 1664,
            author_key: 2176,
            rsvd3: 3204
        }
    }
}
