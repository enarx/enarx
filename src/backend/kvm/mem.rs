// SPDX-License-Identifier: Apache-2.0

use std::os::{
    fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd},
    unix::io::AsRawFd,
};

use iocuddle::{Group, Ioctl, Write};
use kvm_ioctls::VmFd;
use lset::Span;
use mmarinus::{perms, Map};
use x86_64::{PhysAddr, VirtAddr};

const KVM: Group = Group::new(0xAE);
const KVM_SET_USER_MEMORY_REGION2: Ioctl<Write, &Slot> = unsafe { KVM.write(0x49) };
const KVM_MEM_PRIVATE: u32 = 0x04;

pub struct Region {
    slot: Slot,
    backing: Map<perms::ReadWrite>,
}

impl Region {
    pub fn new(slot: Slot, backing: Map<perms::ReadWrite>) -> Self {
        Self { slot, backing }
    }

    #[allow(dead_code)]
    pub fn as_guest(&self) -> Span<PhysAddr, u64> {
        Span {
            start: PhysAddr::new(self.slot.guest_phys_addr),
            count: self.slot.memory_size,
        }
    }

    pub fn as_virt(&self) -> Span<VirtAddr, u64> {
        Span {
            start: VirtAddr::new(self.slot.userspace_addr),
            count: self.slot.memory_size,
        }
    }

    pub fn backing(&self) -> &[u8] {
        self.backing.as_ref()
    }

    pub fn backing_mut(&mut self) -> &mut [u8] {
        self.backing.as_mut()
    }

    pub fn restricted_fd(&self) -> Option<BorrowedFd> {
        self.slot.restricted_fd.as_ref().map(AsFd::as_fd)
    }
}

#[repr(C)]
pub struct Slot {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    restricted_offset: u64,
    restricted_fd: Option<OwnedFd>,
    pad1: u32,
    pad2: [u64; 14],
}

impl Slot {
    /// Create a new memory slot and assign it to a VM.
    pub fn new(
        vm_fd: &mut VmFd,
        slot_index: u32,
        backing_memory: &Map<perms::ReadWrite>,
        guest_phys_addr: u64,
        is_private: bool,
    ) -> std::io::Result<Self> {
        let memory_size = u64::try_from(backing_memory.len()).unwrap();

        // Optionally allocate private memory.
        let restricted_fd = is_private
            .then(|| create_memfd_restricted(memory_size))
            .transpose()?;

        // Create a slot.
        let slot = Self {
            slot: slot_index,
            flags: KVM_MEM_PRIVATE,
            guest_phys_addr,
            memory_size,
            userspace_addr: u64::try_from(backing_memory.addr()).unwrap(),
            restricted_offset: 0,
            restricted_fd,
            pad1: 0,
            pad2: [0; 14],
        };

        // Assign it to the VM.
        KVM_SET_USER_MEMORY_REGION2.ioctl(vm_fd, &slot)?;

        Ok(slot)
    }
}

/// Create a memfd_restricted file descriptor and grow it to `memory_size`.
fn create_memfd_restricted(memory_size: u64) -> std::io::Result<OwnedFd> {
    // Create the file descriptor.
    let memfd_restricted_flags = 0;
    let restricted_fd = unsafe {
        // SAFETY: The `memfd_restricted` has no safety relevant side effects.
        libc::syscall(451, memfd_restricted_flags)
    };
    if restricted_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Convert to a owned file descriptor.
    let restricted_fd = unsafe {
        // SAFETY: We've just acquired the fd.
        OwnedFd::from_raw_fd(restricted_fd as _)
    };

    // Grow the private memory.
    let ret = unsafe { libc::ftruncate(restricted_fd.as_raw_fd(), memory_size as _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(restricted_fd)
}
