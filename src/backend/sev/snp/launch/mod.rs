// SPDX-License-Identifier: Apache-2.0

//! An implementation of the SEV-SNP launch process as a type-state machine.
//! This ensures (at compile time) that the right steps are called in the
//! right order.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
use linux::*;

use super::Version;

use std::io::Result;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

use bitflags::bitflags;
use kvm_bindings::kvm_enc_region;
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
    /// KVM_SNP_INIT ioctl.
    pub fn new(vm_fd: VmFd, sev: V) -> Result<Self> {
        let mut launcher = Launcher {
            vm_fd,
            sev,
            state: PhantomData::default(),
        };

        let init = Init::default();

        let mut cmd = Command::from(&mut launcher.sev, &init);
        SNP_INIT
            .ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Initialize the flow to launch a guest.
    pub fn start(mut self, start: Start<'_>) -> Result<Launcher<Started, V>> {
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
        let launch_update_data = LaunchUpdate::from(update);
        let mut cmd = Command::from(&mut self.sev, &launch_update_data);

        let memory_region = kvm_enc_region {
            addr: update.uaddr.as_ptr() as _,
            size: update.uaddr.len() as _,
        };
        self.vm_fd.register_enc_memory_region(&memory_region)?;

        SNP_LAUNCH_UPDATE
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

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

bitflags! {
    /// Configurable SNP Policy options.
    #[derive(Default)]
    pub struct PolicyFlags: u16 {
        /// Enable if SMT is enabled in the host machine.
        const SMT = 1;

        /// If enabled, association with a migration agent is allowed.
        const MIGRATE_MA = 1 << 2;

        /// If enabled, debugging is allowed.
        const DEBUG = 1 << 3;
    }
}

/// Describes a policy that the AMD Secure Processor will
/// enforce.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The various policy optons are encoded as bit flags.
    pub flags: PolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

impl From<Policy> for u64 {
    fn from(policy: Policy) -> u64 {
        let mut val: u64 = 0;

        let minor_version = u64::from(policy.minfw.minor);
        let mut major_version = u64::from(policy.minfw.major);

        /*
         * According to the SNP firmware spec, bit 1 of the policy flags is reserved and must
         * always be set to 1. Rather than passing this responsibility off to callers, set this bit
         * every time an ioctl is issued to the kernel.
         */
        let flags = policy.flags.bits | 0b10;
        let mut flags_64 = u64::from(flags);

        major_version <<= 8;
        flags_64 <<= 16;

        val |= minor_version;
        val |= major_version;
        val |= flags_64;
        val &= 0x00FFFFFF;

        val
    }
}

/// Encapsulates the various data needed to begin the launch process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Start<'a> {
    /// The userspace address of the migration agent region to be encrypted.
    pub(crate) ma_uaddr: Option<&'a [u8]>,

    /// Describes a policy that the AMD Secure Processor will enforce.
    pub(crate) policy: Policy,

    /// Indicates that this launch flow is launching an IMI for the purpose of guest-assisted migration.
    pub(crate) imi_en: bool,

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

    /// Indicates that this page is part of the IMI of the guest.
    pub(crate) imi_page: bool,

    /// Encoded page type.
    pub(crate) page_type: PageType,

    /// VMPL3 permission mask.
    pub(crate) vmpl3_perms: VmplPerms,

    /// VMPL2 permission mask.
    pub(crate) vmpl2_perms: VmplPerms,

    /// VMPL1 permission mask.
    pub(crate) vmpl1_perms: VmplPerms,
}

impl<'a> Update<'a> {
    /// Encapsulate all data needed for the SNP_LAUNCH_UPDATE ioctl.
    pub fn new(
        start_gfn: u64,
        uaddr: &'a [u8],
        imi_page: bool,
        page_type: PageType,
        perms: (VmplPerms, VmplPerms, VmplPerms),
    ) -> Self {
        Self {
            start_gfn,
            uaddr,
            imi_page,
            page_type,
            vmpl3_perms: perms.2,
            vmpl2_perms: perms.1,
            vmpl1_perms: perms.0,
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
    /// The userspace address of the encrypted region.
    pub(crate) id_block: Option<&'a [u8]>,

    /// The userspace address of the authentication information of the ID block.
    pub(crate) id_auth: Option<&'b [u8]>,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this
    /// value.
    pub(crate) host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
}

impl<'a, 'b> Finish<'a, 'b> {
    /// Encapsulate all data needed for the SNP_LAUNCH_FINISH ioctl.
    pub fn new(
        id_block: Option<&'a [u8]>,
        id_auth: Option<&'b [u8]>,
        host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
    ) -> Self {
        Self {
            id_block,
            id_auth,
            host_data,
        }
    }
}
