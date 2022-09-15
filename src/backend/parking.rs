// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use libc::timespec;
use tracing::{instrument, trace};

pub(crate) static THREAD_PARK: Parking = Parking::const_default();

#[derive(Debug)]
pub(crate) struct Parking(AtomicU32);

// Notes about memory ordering:
//
// Memory ordering is only relevant for the relative ordering of operations
// between different variables. Even Ordering::Relaxed guarantees a
// monotonic/consistent order when looking at just a single atomic variable.
//
// So, since this parker is just a single atomic variable, we only need to look
// at the ordering guarantees we need to provide to the 'outside world'.
//
// The only memory ordering guarantee that parking and unparking provide, is
// that things which happened before unpark() are visible on the thread
// returning from park() afterwards. Otherwise, it was effectively unparked
// before unpark() was called.
//
// In other words, unpark() needs to synchronize with the part of park() that
// consumes the value and returns.
//
// This is done with a release-acquire synchronization, by using
// Ordering::Release when increasing the value in unpark(), and using
// Ordering::Acquire when checking for this value in park().
impl Parking {
    pub const fn const_default() -> Self {
        Self(AtomicU32::new(0))
    }

    #[instrument(level = "trace")]
    pub(crate) fn park(
        &self,
        expected: u32,
        timespec: Option<&timespec>,
    ) -> sallyport::Result<u32> {
        let timespec = timespec.map_or(0, |t| t as *const _ as usize);
        let futex_ptr = &self.0 as *const AtomicU32;

        loop {
            // No need to wait if the value already changed.
            let val = self.0.load(Ordering::Acquire);
            if val != expected {
                trace!("futex value changed to {val}");
                return Ok(val);
            }

            trace!("futex: FUTEX_WAIT_BITSET {futex_ptr:p} {expected} {timespec:#?}");
            let r = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    futex_ptr,
                    libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                    expected,
                    timespec,
                    ptr::null::<u32>(), // This argument is unused for FUTEX_WAIT_BITSET.
                    !0u32,              // Wait on all bits for FUTEX_WAIT_BITSET.
                )
            };

            if r == 0 {
                let val = self.0.load(Ordering::Acquire);
                trace!("futex: FUTEX_WAIT_BITSET {futex_ptr:p} {expected} {timespec:#?} = 0 (val={val})");
                return Ok(val);
            }

            let err = io::Error::last_os_error().raw_os_error().unwrap();
            trace!("futex: FUTEX_WAIT_BITSET {futex_ptr:p} {expected} {timespec:#?} = -{err}");

            match err {
                libc::EINTR => continue,
                e => return Err(e),
            }
        }
    }

    #[instrument(level = "trace")]
    pub(crate) fn unpark(&self) {
        self.0.fetch_add(1, Ordering::Release);

        let futex_ptr = &self.0 as *const AtomicU32;
        let op = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;
        trace!("futex: {futex_ptr:p} FUTEX_WAKE");
        unsafe {
            libc::syscall(libc::SYS_futex, futex_ptr, op, i32::MAX);
        }
    }
}
