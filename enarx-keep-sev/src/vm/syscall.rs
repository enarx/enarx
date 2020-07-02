// SPDX-License-Identifier: Apache-2.0

/// Some system call parameters contain pointers to userspace memory (such as the `write` syscall).
/// These values are *guest physical addresses*, so they must be "fixed up" to be *host virtual
/// addresses* so that the host can transparently proxy the syscall.
///
/// The `SyscallFixup` type contains a slice of integers that correspond to an index within the
/// `sallyport::Request.args` array. So, for a given `SyscallFixup` table, each index indicated
/// by the `SyscallFixup` table *must* be modified to be a host virtual address in order to
/// successfully proxy the syscall.
///
/// Some syscalls won't require any fixups and not all syscalls will use the same fixups.
type SyscallFixup = &'static [usize];

#[allow(dead_code)]
mod param {
    pub const RDI: usize = 0;
    pub const RSI: usize = 1;
    pub const RDX: usize = 2;
    pub const R10: usize = 3;
    pub const R8: usize = 4;
    pub const R9: usize = 5;
}

use param::RSI;

/// Get the fixup table for a given syscall number, if any.
#[inline]
fn syscall_fixup_table(syscall: libc::c_long) -> Option<SyscallFixup> {
    match syscall {
        libc::SYS_write => Some(&[RSI]),
        _ => None,
    }
}

pub fn syscall(mut req: sallyport::Request, offset: u64) -> sallyport::Reply {
    if let Some(fixups) = syscall_fixup_table(req.num.raw() as _) {
        for fixup in fixups {
            let guest = req.arg[*fixup];
            let host = guest.raw() + (offset as usize);
            req.arg[*fixup] = memory::Register::from_raw(host);
        }
    }

    unsafe { req.syscall() }
}
