// SPDX-License-Identifier: Apache-2.0

//! Host <-> Shim Communication

use core::convert::TryFrom;
use core::mem::size_of;

use array_const_fn_init::array_const_fn_init;
use primordial::Page as Page4KiB;
use primordial::Register;
use sallyport::syscall::enarx::MemInfo;
use sallyport::syscall::{SYS_ENARX_BALLOON_MEMORY, SYS_ENARX_MEM_INFO};
use sallyport::KVM_SYSCALL_TRIGGER_PORT;
use sallyport::{request, Block};
use spinning::Lazy;
use x86_64::instructions::port::Port;
use x86_64::structures::paging::{Page, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::addr::{HostVirtAddr, ShimPhysUnencryptedAddr};
use crate::debug::_enarx_asm_triple_fault;
use crate::snp::ghcb::GHCB;
use crate::snp::snp_active;
use crate::spin::{RacyCell, RwLocked};

/// Host file descriptor
#[derive(Copy, Clone)]
pub struct HostFd(libc::c_int);

impl HostFd {
    /// Extracts the raw file descriptor.
    ///
    /// This method does **not** pass ownership of the raw file descriptor
    /// to the caller. The descriptor is only guaranteed to be valid while
    /// the original object has not yet been destroyed.
    pub fn as_raw_fd(self) -> libc::c_int {
        self.0
    }

    /// Constructs a new instance of `Self` from the given raw file
    /// descriptor.
    ///
    /// # Safety
    ///
    /// This function is unsafe as the primitives currently returned
    /// have the contract that they are the sole owner of the file
    /// descriptor they are wrapping. Usage of this function could
    /// accidentally allow violating this contract which can cause memory
    /// unsafety in code that relies on it being true.
    pub unsafe fn from_raw_fd(fd: libc::c_int) -> Self {
        Self(fd)
    }
}

const MAX_BLOCK_NR: usize = 512;

fn return_empty_option<'a>(_i: usize) -> Option<&'a mut Block> {
    None
}

/// The static HostCall RwLocked
///
/// # Safety
/// `HOST_CALL_ALLOC` is  the only way to get access to `_ENARX_SALLYPORT` and
/// is guarded with a `RwLocked`
pub static HOST_CALL_ALLOC: Lazy<RwLocked<HostCallAllocator>> = Lazy::new(|| {
    extern "C" {
        /// Extern
        pub static _ENARX_SALLYPORT_START: RacyCell<Page4KiB>;
        /// Extern
        pub static _ENARX_SALLYPORT_END: RacyCell<Page4KiB>;
    }

    if snp_active() {
        // For SEV-SNP mark the sallyport pages as shared/unencrypted

        let npages = (unsafe {
            &_ENARX_SALLYPORT_END as *const _ as usize
                - &_ENARX_SALLYPORT_START as *const _ as usize
        }) / Page::<Size4KiB>::SIZE as usize;

        GHCB.set_memory_shared(
            VirtAddr::from_ptr(unsafe { &_ENARX_SALLYPORT_START }),
            npages,
        );
    }

    let block_mut: *mut Block = unsafe { _ENARX_SALLYPORT_START.get() as *mut _ };

    let nr_syscall_blocks = unsafe {
        (&_ENARX_SALLYPORT_END as *const _ as usize - &_ENARX_SALLYPORT_START as *const _ as usize)
            / size_of::<Block>()
    };

    assert!(nr_syscall_blocks <= 512);

    let mut hostcall_allocator = HostCallAllocator(array_const_fn_init![return_empty_option; 512]);

    for i in 0..nr_syscall_blocks {
        (hostcall_allocator.0)[i].replace(unsafe { &mut *block_mut.add(i) });
    }

    RwLocked::<HostCallAllocator>::new(hostcall_allocator)
});

/// Allocator for all `sallyport::Block`
pub struct HostCallAllocator([Option<&'static mut Block>; MAX_BLOCK_NR]);

impl RwLocked<HostCallAllocator> {
    /// Try to allocate a `HostCall` object to use a `sallyport::Block`
    pub fn try_alloc(&self) -> Option<HostCall> {
        let mut this = self.write();
        this.0
            .iter_mut()
            .enumerate()
            .find(|(_i, x)| x.is_some())
            .map(|(i, ele)| HostCall {
                block_index: i as _,
                block: ele.take(),
            })
    }
}

/// Communication with the Host
pub struct HostCall {
    block_index: u16,
    block: Option<&'static mut Block>,
}

impl Drop for HostCall {
    fn drop(&mut self) {
        HOST_CALL_ALLOC.write().0[self.block_index as usize] = self.block.take();
    }
}

impl HostCall {
    /// Causes a `#VMEXIT` for the host to process the data in the shared memory
    ///
    /// Returns the contents of the shared memory reply status, the host might have
    /// written.
    ///
    /// # Safety
    ///
    /// The parameters returned can't be trusted.
    #[inline(always)]
    pub unsafe fn hostcall(&mut self) -> sallyport::Result {
        if !snp_active() {
            let mut port = Port::<u16>::new(KVM_SYSCALL_TRIGGER_PORT);

            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            port.write(self.block_index);

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        } else {
            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            GHCB.do_io_out(KVM_SYSCALL_TRIGGER_PORT, self.block_index);
            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        }

        self.block.as_mut().unwrap().msg.rep.into()
    }

    /// Return reference to the inner `Block`
    pub fn as_block(&self) -> &Block {
        self.block.as_ref().unwrap()
    }

    /// Return mutable reference to the inner `Block`
    pub fn as_mut_block(&mut self) -> &mut Block {
        self.block.as_mut().unwrap()
    }

    /// Write `bytes` to a host file descriptor `fd`
    ///
    /// Write at most `Block::buf_capacity()` bytes.
    /// Handle it like write(2) and call it in a loop until all bytes are written.
    ///
    /// # Safety
    ///
    /// The parameters returned can't be trusted.
    pub unsafe fn write(&mut self, fd: libc::c_int, bytes: &[u8]) -> sallyport::Result {
        let cursor = self.block.as_mut().unwrap().cursor();
        let (_, buf) = cursor.copy_from_slice(bytes).or(Err(libc::EMSGSIZE))?;
        let phys_unencrypted = ShimPhysUnencryptedAddr::try_from(buf.as_ptr()).unwrap();

        let host_virt: HostVirtAddr<_> = phys_unencrypted.into();

        self.block.as_mut().unwrap().msg.req =
            request!(libc::SYS_write => fd, host_virt, buf.len());

        self.hostcall()
    }

    /// Balloon the memory
    pub fn balloon(&mut self, pages: usize, gpa: PhysAddr) -> Result<usize, libc::c_int> {
        self.block.as_mut().unwrap().msg.req =
            request!(SYS_ENARX_BALLOON_MEMORY => 12, pages, gpa.as_u64());
        Ok(unsafe { self.hostcall() }?[0].into())
    }

    /// Get host memory info
    pub fn mem_info(&mut self) -> Result<MemInfo, libc::c_int> {
        self.block.as_mut().unwrap().msg.req = request!(SYS_ENARX_MEM_INFO);

        let _result = unsafe { self.hostcall() }?;

        let block = self.as_mut_block();
        let c = block.cursor();

        let (_, mem_info) = unsafe { c.read::<MemInfo>() }.or(Err(libc::EMSGSIZE))?;

        Ok(mem_info)
    }

    /// Exit the shim with a `status` code
    ///
    /// # Panics
    ///
    /// Panics, if the shim resumes to run.
    #[inline(always)]
    pub fn exit_group(&mut self, status: i32) -> ! {
        unsafe {
            let request = request!(libc::SYS_exit_group => status);
            self.block.as_mut().unwrap().msg.req = request;

            let _ = self.hostcall();

            unreachable!()
        }
    }
}

/// Write all `bytes` to a host file descriptor `fd`
#[inline(always)]
pub fn shim_write_all(fd: HostFd, bytes: &[u8]) -> Result<(), libc::c_int> {
    let bytes_len = bytes.len();
    let mut to_write = bytes_len;

    let mut host_call = HOST_CALL_ALLOC.try_alloc().ok_or(libc::EIO)?;

    loop {
        let written = unsafe {
            let next = bytes_len.checked_sub(to_write).ok_or(libc::EFAULT)?;
            host_call
                .write(fd.as_raw_fd(), &bytes[next..])
                .map(|regs| usize::from(regs[0]))
        }?;
        // be careful with `written` as it is untrusted
        to_write = to_write.checked_sub(written).ok_or(libc::EIO)?;
        if to_write == 0 {
            break;
        }
    }

    Ok(())
}

/// Exit the shim with a `status` code
///
/// Reverts to a triple fault, which causes a `#VMEXIT` and a KVM shutdown,
/// if it cannot talk to the host.
pub fn shim_exit(status: i32) -> ! {
    if let Some(mut host_call) = HOST_CALL_ALLOC.try_alloc() {
        host_call.exit_group(status)
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() }
}
