// SPDX-License-Identifier: Apache-2.0

//! Host <-> Shim Communication

use sallyport::{request, Block};
use x86_64::instructions::port::Port;

use crate::addr::{ShimPhysAddr, ShimVirtAddr};
use crate::asm::_enarx_asm_triple_fault;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU64, Ordering};
use enarx_keep_sev_shim::SYSCALL_TRIGGER_PORT;
use memory::{Address, Page, Register};
use x86_64::instructions::hlt;

/// The address of the unencrypted page used to communicate with the host
static mut HOSTCALL_VIRT_ADDR: AtomicU64 = AtomicU64::new(0);

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

/// Communication with the Host
pub struct HostCall<'a>(&'a mut Block);

impl<'a> HostCall<'a> {
    /// Initialize the HostCall machinery with the address of the shared page
    ///
    /// # Panics
    ///
    /// Panics, if it is initialized more than once.
    #[inline(always)]
    pub fn init(address: ShimVirtAddr<*mut Page>) {
        let prev = unsafe {
            HOSTCALL_VIRT_ADDR.swap(
                Address::<u64, *mut Page>::from(address).raw(),
                Ordering::Release,
            )
        };
        if prev != 0 {
            panic!("HostCall already initialized");
        }
    }

    /// Acquire a HostCall instance to communicate with the host.
    ///
    /// Returns None, if it is already in use, which might happen in an interrupt;
    /// or if there are multiple CPUs.
    ///
    /// # Safety
    ///
    /// exclusive mutable access is ensured via an Atomic variable
    #[inline(always)]
    pub fn try_lock() -> Option<Self> {
        // Try to take out the virtual address out of the global variable
        let address = unsafe { HOSTCALL_VIRT_ADDR.swap(0, Ordering::Acquire) };
        if address == 0 {
            // Already in use
            None
        } else {
            Some(unsafe { Self(&mut *(address as *mut Block)) })
        }
    }

    /// Acquire a HostCall instance to communicate with the host.
    ///
    /// # Caution
    ///
    /// Do not call this in interrupts, as it can cause deadlocks
    ///
    /// # Safety
    ///
    /// exclusive mutable access is ensured via an Atomic variable
    #[inline(always)]
    pub fn lock() -> Self {
        loop {
            // Try to take out the virtual address out of the global variable
            let address = unsafe { HOSTCALL_VIRT_ADDR.swap(0, Ordering::Acquire) };
            if address == 0 {
                // Already in use
                core::sync::atomic::spin_loop_hint();
            } else {
                return unsafe { Self(&mut *(address as *mut Block)) };
            }
        }
    }

    /// Causes a `#VMEXIT` for the host to process the data in the shared memory
    ///
    /// Returns the contents of the shared memory reply status, the host might have
    /// written.
    ///
    /// # Safety
    ///
    /// The parameters returned can't be trusted.
    #[inline(always)]
    unsafe fn hostcall(&mut self) -> Result<[Register<usize>; 2], libc::c_int> {
        let mut port = Port::<u16>::new(SYSCALL_TRIGGER_PORT);
        port.write(1 as u16);
        self.0.msg.rep.into()
    }

    /// Write `bytes` to a host file descriptor `fd`
    ///
    /// Write at most `Block::buf_capacity()` bytes.
    /// Handle it like write(2) and call it in a loop until all bytes are written.
    ///
    /// # Safety
    ///
    /// The parameters returned can't be trusted.
    pub unsafe fn write(&mut self, fd: usize, bytes: &[u8]) -> Result<libc::c_int, libc::c_int> {
        let cursor = self.0.cursor();
        let buf = cursor.copy_slice(bytes).or(Err(libc::EMSGSIZE))?;

        let buf_address = Address::from(buf.as_ptr());
        let shim_virt_address = ShimVirtAddr::try_from(buf_address).map_err(|_| libc::EFAULT)?;

        let phys = ShimPhysAddr::from(shim_virt_address);
        let request = request!(libc::SYS_write => fd, phys, buf.len());

        self.0.msg.req = request;
        self.hostcall().map(|r| r[0].raw() as _)
    }

    /// Exit the shim with a `status` code
    ///
    /// # Panics
    ///
    /// Panics, if the shim resumes to run.
    #[inline(always)]
    pub fn exit_group(&mut self, status: u32) -> ! {
        unsafe {
            let request = request!(libc::SYS_exit_group => status);
            self.0.msg.req = request;

            let _ = self.hostcall();

            unreachable!()
        }
    }
}

impl<'a> Drop for HostCall<'a> {
    fn drop(&mut self) {
        // Put back in the virtual address in the global variable
        let prev = unsafe { HOSTCALL_VIRT_ADDR.swap(self.0 as *mut _ as _, Ordering::Release) };
        assert_eq!(prev, 0);
    }
}

/// Write all `bytes` to a host file descriptor `fd`
#[inline(always)]
pub fn shim_write_all(fd: HostFd, bytes: &[u8]) -> Result<(), libc::c_int> {
    let fd = usize::try_from(fd.as_raw_fd()).map_err(|_| libc::EBADF)?;
    let bytes_len = bytes.len();
    let mut to_write = bytes_len;

    let mut host_call = HostCall::try_lock().ok_or(libc::EIO)?;

    loop {
        let written = unsafe {
            let next = bytes_len.checked_sub(to_write).ok_or(libc::EFAULT)?;
            host_call.write(fd, &bytes[next..])?
        };
        // be careful with `written` as it is untrusted
        to_write = to_write
            .checked_sub(usize::try_from(written).map_err(|_| libc::EIO)?)
            .ok_or(libc::EIO)?;
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
pub fn shim_exit(status: u32) -> ! {
    if let Some(mut host_call) = HostCall::try_lock() {
        host_call.exit_group(status)
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() };
    // in case the triple fault did not cause a shutdown
    loop {
        hlt()
    }
}
