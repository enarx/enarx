// SPDX-License-Identifier: Apache-2.0

//! Host <-> Shim Communication

use crate::addr::{HostVirtAddr, ShimPhysAddr, ShimVirtAddr};
use crate::asm::_enarx_asm_triple_fault;
use crate::hostlib::SYSCALL_TRIGGER_PORT;
use crate::SHIM_HOSTCALL_VIRT_ADDR;
use core::convert::TryFrom;
use memory::{Address, Page};
use sallyport::{request, Block};
use spinning::Mutex;
use x86_64::instructions::port::Port;

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

lazy_static! {
    /// The static HostCall Mutex
    pub static ref HOST_CALL: Mutex<HostCall<'static>> = {
        let address = SHIM_HOSTCALL_VIRT_ADDR.read().unwrap();
        let shared_page_addr = Address::from(address.as_ptr::<*mut Page>())
            .try_cast()
            .unwrap();
        let shared_page: ShimVirtAddr<*mut Page> = ShimVirtAddr::try_from(shared_page_addr).unwrap();

        Mutex::<HostCall<'static>>::const_new(spinning::RawMutex::const_new(), unsafe {
            HostCall(&mut *(Address::<u64, *mut Page>::from(shared_page).raw() as *mut Block))
        })
    };
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
    pub unsafe fn hostcall(&mut self) -> sallyport::Result {
        let mut port = Port::<u16>::new(SYSCALL_TRIGGER_PORT);
        port.write(1);
        self.0.msg.rep.into()
    }

    /// Return reference to the inner `Block`
    pub fn as_block(&self) -> &Block {
        self.0
    }

    /// Return mutable reference to the inner `Block`
    pub fn as_mut_block(&mut self) -> &mut Block {
        self.0
    }

    /// Write `bytes` to a host file descriptor `fd`
    ///
    /// Write at most `Block::buf_capacity()` bytes.
    /// Handle it like write(2) and call it in a loop until all bytes are written.
    ///
    /// # Safety
    ///
    /// The parameters returned can't be trusted.
    pub unsafe fn write(&mut self, fd: usize, bytes: &[u8]) -> sallyport::Result {
        let cursor = self.0.cursor();
        let (_, buf) = cursor.copy_slice(bytes).or(Err(libc::EMSGSIZE))?;

        let buf_address = Address::from(buf.as_ptr());
        let shim_virt_address = ShimVirtAddr::try_from(buf_address).map_err(|_| libc::EFAULT)?;
        let host_virt: HostVirtAddr<_> = ShimPhysAddr::from(shim_virt_address).into();

        self.0.msg.req = request!(libc::SYS_write => fd, host_virt, buf.len());
        self.hostcall()
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

    let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;

    loop {
        let written = unsafe {
            let next = bytes_len.checked_sub(to_write).ok_or(libc::EFAULT)?;
            host_call
                .write(fd, &bytes[next..])
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
pub fn shim_exit(status: u32) -> ! {
    if let Some(mut host_call) = HOST_CALL.try_lock() {
        host_call.exit_group(status)
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() };
}
