// SPDX-License-Identifier: Apache-2.0

//! Modularized components for creating the initial state of VM-based keeps.

pub mod x86;

use std::mem::{align_of, size_of};

use mmarinus::{perms::ReadWrite, Map};
use primordial::Page;
use x86_64::VirtAddr;

use crate::backend::kvm::shim::BootInfo;
use crate::backend::kvm::Hook;
use crate::binary::Component;
use crate::sallyport::Block;

/// The `Arch` trait enables architecture-specific setup for the initial
/// image.
///
/// For example, an X86_64 implementation of this could be a struct
/// that places and configures page tables.
pub trait Arch {
    fn commit(&mut self, backing: &Map<ReadWrite>, hook: &impl Hook);
}

/// The `Image` struct facilitates the construction of a VM image based
/// on what architecture it is meant for.
///
/// NOTE: This struct is meant to be superimposed over the initial address
/// space starting at address zero; otherwise the image setup will be wrong.
/// To do this, cast the beginning address of the `mmap`'d address space into
/// an `Image` struct.
#[repr(C, align(4096))]
pub struct Image<A: Arch> {
    pub arch: A,
}

impl<A: Arch> Image<A> {
    /// Performs setup and commits the image to the address space.
    ///
    /// NOTE: this must only be called through a pointer that superimposes
    /// the `Image` struct over the initial address space.
    pub fn commit(
        &mut self,
        backing: &Map<ReadWrite>,
        boot_info: &BootInfo,
        hook: &impl Hook,
        components: &mut [(&mut Component, usize)],
    ) {
        assert_eq!(backing.addr() % align_of::<Self>(), 0);
        assert!(
            boot_info.mem_size
                >= size_of::<Self>() + boot_info.nr_syscall_blocks * size_of::<Block>()
        );

        self.arch.commit(backing, hook);

        // Install the BootInfo struct to the first shared page.
        unsafe {
            let syscall_block = (self as *mut _ as *mut u8).add(size_of::<Self>()) as *mut BootInfo;
            std::ptr::copy_nonoverlapping(boot_info, syscall_block, 1);
        }

        // Load the shim and code.
        for (component, offset) in components {
            self.load_component(VirtAddr::new(backing.addr() as _), component, *offset);
        }
    }

    fn load_component(&mut self, start: VirtAddr, component: &mut Component, offset: usize) {
        use std::slice::from_raw_parts_mut;

        if component.pie {
            component.entry += offset;
            for seg in &mut component.segments {
                seg.dst += offset;
            }
        }

        for seg in &component.segments {
            let dst = VirtAddr::new(seg.dst as u64 + start.as_u64());
            let dst = unsafe { from_raw_parts_mut(dst.as_mut_ptr::<Page>(), seg.src.len()) };
            dst.copy_from_slice(&seg.src[..]);
        }
    }

    pub fn syscall_region_start(&self) -> VirtAddr {
        unsafe { VirtAddr::from_ptr((self as *const Self).add(1)) }
    }
}
