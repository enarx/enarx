// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use kvm_ioctls::VmFd;
use mmarinus::{perms, Map};

const KVM_MEM_PRIVATE: u32 = 0x04;
#[cfg(target_env = "musl")]
const KVM_SET_USER_MEMORY_REGION: std::ffi::c_int = 0x4020ae46;
#[cfg(not(target_env = "musl"))]
const KVM_SET_USER_MEMORY_REGION: std::ffi::c_ulong = 0x4020ae46;

// TODO: Should contain instead being `kvm_userspace_memory_region_ext` once it is in the mainline
// kernel and `kvm_ioctls` crate.
#[repr(C)]
pub struct Slot {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub restricted_offset: u64,
    pub restricted_fd: u32,
    pub pad1: u32,
    pub pad2: [u64; 14],
}

pub type Region = (Slot, Map<perms::ReadWrite>);

impl Drop for Slot {
    fn drop(&mut self) {
        if self.restricted_fd != 0 {
            unsafe { libc::close(self.restricted_fd as _) };
        }
    }
}

impl Slot {
    pub fn new(
        vm_fd: &VmFd,
        slot_index: u32,
        slot_addr: u64,
        guest_phys_addr: u64,
        memory_size: u64,
        is_private: bool,
    ) -> std::io::Result<Self> {
        if is_private {
            // memfd_restricted() syscall
            let restricted_fd: i32 = unsafe {
                let ret: i32;
                std::arch::asm!(
                    "syscall",
                    in("rax") 451,
                    in("rdi") 0,
                    in("rsi") 0,
                    in("rdx") 0,
                    out("rcx") _,
                    out("r11") _,
                    lateout("rax") ret,
                );
                ret
            };

            if restricted_fd < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let ret = unsafe { libc::ftruncate(restricted_fd, memory_size as _) };
            if ret < 0 {
                unsafe { libc::close(restricted_fd as _) };
                return Err(std::io::Error::last_os_error());
            }

            let slot = Self {
                slot: slot_index,
                flags: KVM_MEM_PRIVATE,
                guest_phys_addr,
                memory_size,
                userspace_addr: slot_addr,
                restricted_offset: 0,
                restricted_fd: restricted_fd as _,
                pad1: 0,
                pad2: [0; 14],
            };

            if unsafe { libc::ioctl(vm_fd.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &slot) } < 0 {
                unsafe { libc::close(restricted_fd as _) };
                Err(std::io::Error::last_os_error())
            } else {
                Ok(slot)
            }
        } else {
            let slot = Self {
                slot: slot_index,
                flags: 0,
                guest_phys_addr,
                memory_size,
                userspace_addr: slot_addr,
                restricted_offset: 0,
                restricted_fd: 0,
                pad1: 0,
                pad2: [0; 14],
            };

            if unsafe { libc::ioctl(vm_fd.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &slot) } < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(slot)
            }
        }
    }
}
