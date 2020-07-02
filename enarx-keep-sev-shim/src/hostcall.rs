// SPDX-License-Identifier: Apache-2.0

//! Host <-> Shim Communication

use sallyport::{request, Block};
use x86_64::instructions::port::Port;

use crate::addr::{ShimPhysAddr, ShimVirtAddr};
use crate::asm::_enarx_asm_triple_fault;
use crate::mutex_singleton;
use core::convert::TryFrom;
use enarx_keep_sev_shim::SYSCALL_TRIGGER_PORT;
use memory::{Address, Page, Register};

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

mutex_singleton! {
    static mut HOST_CALL: HostCallMutex<HostCall<'static>>;
}

impl HostCallMutex {
    /// Initialize the HostCall machinery with the address of the shared page
    ///
    /// # Panics
    ///
    /// Panics, if it is initialized more than once.
    ///
    /// # Safety
    ///
    /// Unsafe, because the caller has to ensure the page is used only once
    /// and defined to be used as a communication with the host.
    #[inline(always)]
    pub unsafe fn init(address: ShimVirtAddr<*mut Page>) {
        HostCallMutex::init_global(HostCall(
            &mut *(Address::<u64, *mut Page>::from(address).raw() as *mut Block),
        ));
    }
}

/// Communication with the Host
pub struct HostCall<'a>(&'a mut Block);

impl<'a> HostCall<'a> {
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
        let bytes = &bytes[..core::cmp::min(bytes.len(), Block::buf_capacity())];

        let buf_address = Address::from(self.0.buf.as_mut_ptr());
        let shim_virt_address = ShimVirtAddr::try_from(buf_address).map_err(|_| libc::EFAULT)?;

        let phys = ShimPhysAddr::from(shim_virt_address);
        let request = request!(libc::SYS_write => fd, phys, bytes.len());

        self.0.msg.req = request;
        self.0.buf[..bytes.len()].copy_from_slice(bytes);
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

/// Write all `bytes` to a host file descriptor `fd`
#[inline(always)]
pub fn shim_write_all(fd: HostFd, bytes: &[u8]) -> Result<(), libc::c_int> {
    let fd = usize::try_from(fd.as_raw_fd()).map_err(|_| libc::EBADF)?;
    let bytes_len = bytes.len();
    let mut to_write = bytes_len;

    let mut host_call = HostCallMutex::try_lock().ok_or(libc::EIO)?;

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
    if let Some(mut host_call) = HostCallMutex::try_lock() {
        host_call.exit_group(status)
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() };
}
