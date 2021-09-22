// SPDX-License-Identifier: Apache-2.0

//! API for the hypervisor-microkernel boundary
//!
//! `sallyport` is a protocol crate for proxying service requests (such as syscalls) from an Enarx Keep
//! to the host. A [sally port](https://en.wikipedia.org/wiki/Sally_port) is a secure gateway through
//! which a defending army might "sally forth" from the protection of their fortification.
//!
//! An astute reader may notice that `sallyport` is a thin layer around the Linux syscall ABI as it is
//! predicated on the conveyance of a service request number (such as `rax` for x86_64) as well as the
//! maximum number (6) of syscall parameter registers:
//!
//! | Architecture | arg 1 | arg 2 | arg 3 | arg 4 | arg 5 | arg 6 |
//! | ------------ | ----- | ----- | ----- | ----- | ----- | ----- |
//! | x86_64       | rdi   | rsi   | rdx   | r10   | r8    | r9    |
//!
//! _The above table was taken from the syscall(2) man page_
//!
//! Note that `sallyport` is meant to generalize over all architectures that Enarx anticipates proxying
//! syscalls to, not just x86_64 which was listed in the above table for illustration purposes.
//!
//! ## Usage
//!
//! `sallyport` works by providing the host with the most minimal register context it requires to
//! perform the syscall on the Keep's behalf. In doing so, the host can immediately call the desired
//! syscall without any additional logic required. This "register context" is known as a `Message` in
//! `sallyport` parlance.
//!
//! The `Message` union has two representations:
//!
//! 1. `Request`: The register context needed to perform a request or syscall. This includes an identifier
//! and up to the 6 maximum syscall parameter registers expected by the Linux syscall ABI.
//! 2. `Reply`: A response from the host. This representation exists to cater to how each architecture
//! indicates a return value.
//!
//! The `Message` union serves as the header for a `Block` struct, which will be examined next.
//!
//! The `Block` struct is a page-sized buffer which must be written to a page that is accessible
//! to both the host and the Keep to facilitate request proxying. The region of memory that is
//! left over after storing the `Message` header on the block should be used for storing additional
//! parameters that must be shared with the host so it can complete the service request. In the
//! context of a syscall, this would be the sequence bytes to be written with a `write` syscall.
//!
//! If the Keep forms a request that requires additional parameter data to be written to the `Block`,
//! the register context _must_ reflect this. For example, the second parameter to the `write` syscall
//! is a pointer to the string of bytes to be written. In this case, the `Keep` must ensure the
//! second register parameter points to the location where the bytes have been written _within the `Block`,
//! **NOT** a pointer to its protected address space_. Furthermore, once the request has been proxied, it is
//! the Keep's responsibility to propagate any potentially modified data back to its protected pages.
//!
//! ## Example
//!
//! Here's an example of how the `sallyport` protocol might be used to proxy a syscall between
//! the host and a protected virtual machine:
//!
//! 1. The workload within the Keep makes a `write` syscall.
//! 1. The shim traps all syscalls, and notices this is a `write` syscall.
//! 1. The shim writes an empty `Block` onto the page it shares with the untrusted host.
//! 1. The shim copies the bytes that the workload wants to write onto the data region of the `Block`. It is now
//! accessible to the host.
//! 1. The shim modifies the `Message` header to be a `Request` variant. In the case of the `write` syscall, the shim:
//!     1. Sets the request `num` to the Linux integral value for `SYS_write`.
//!     1. Furnishes the register context's syscall arguments:
//!         1. `arg[0]` = The file descriptor to write to.
//!         1. `arg[1]` = The address _within the `Block`_ where the bytes have been copied to.
//!         1. `arg[2]` = The number of bytes that the `write` syscall should emit from the bytes pointed to
//!         in the second parameter.
//! 1. The shim yields control to the untrusted host, in which host-side Enarx code realizes it must proxy a syscall.
//! 1. The host-side Enarx code can invoke the syscall immediately using the values in the `Block`'s `Message` header.
//! 1. Once the syscall is complete, the host-side Enarx code can update the `Block`'s header and set it to a
//! `Reply` variant of the `Message` union and write the syscall return code to it.
//! 1. The host-side Enarx code returns control to the shim.
//! 1. The shim examines the `Reply` in the `Message` header of the `Block` and propagates any mutated data back to
//! the protected address space. It may then return control to its workload.

#![cfg_attr(feature = "asm", feature(asm))]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

pub mod elf;
pub mod syscall;
mod tests;
pub mod untrusted;

use core::mem::size_of;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use primordial::{Page, Register};

/// The sallyport version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The sallyport version requires
///
/// This value provides a semver version requirement. It insists that the
/// other side must use a compatible release to this one. For example, if
/// the `VERSION` of sallyport is 1.2.3, `REQUIRES` will contain `^1.2.3`.
///
/// See [this link](https://docs.rs/semver/1.0.0/semver/enum.Op.html#opcaretcompatible-updates)
/// for more details.
pub const REQUIRES: [u8; VERSION.len() + 1] = {
    let mut value = [0u8; VERSION.len() + 1];
    let mut i = 0;

    value[0] = b'^';
    while i < VERSION.len() {
        value[i + 1] = VERSION.as_bytes()[i];
        i += 1;
    }

    value
};

/// I/O port used to trigger an exit to the host (`#VMEXIT`) for KVM driven shims.
pub const KVM_SYSCALL_TRIGGER_PORT: u16 = 0xFF;

/// The maximum size of a UDP packet
///
/// The maximum UDP message size is 65507, as determined by the following formula:
/// 0xffff - (sizeof(minimal IP Header) + sizeof(UDP Header)) = 65535-(20+8) = 65507
pub const MAX_UDP_PACKET_SIZE: usize = 65507;

/// Creates a Request instance
#[macro_export]
macro_rules! request {
    ($num:expr) => {
        $crate::Request { num: $num.into(), arg: [Register::default(); 7] }
    };

    ($num:expr => $($arg:expr),*) => {{
        let args = [$($arg.into()),*];
        $crate::Request {
            num: $num.into(),
            arg: [
                args.get(0).copied().unwrap_or_default(),
                args.get(1).copied().unwrap_or_default(),
                args.get(2).copied().unwrap_or_default(),
                args.get(3).copied().unwrap_or_default(),
                args.get(4).copied().unwrap_or_default(),
                args.get(5).copied().unwrap_or_default(),
                args.get(6).copied().unwrap_or_default(),
            ]
        }
    }};
}

/// A request
///
/// The `Request` struct is the most minimal representation of the register context
/// needed for service requests from the microkernel to the hypervisor. An example
/// of such a request would be proxying a system call.
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug)]
pub struct Request {
    /// The syscall number for the request
    ///
    /// See, for example, libc::SYS_exit.
    pub num: Register<usize>,

    /// The syscall argument registers
    ///
    /// At most 7 syscall arguments can be provided.
    pub arg: [Register<usize>; 7],
}

impl Request {
    /// Issues the requested syscall and returns the reply
    ///
    /// # Safety
    ///
    /// This function is unsafe because syscalls can't be made generically safe.
    #[cfg(feature = "asm")]
    pub unsafe fn syscall(&self) -> Reply {
        let rax: usize;
        let rdx: usize;

        asm!(
        "syscall",
        inlateout("rax") usize::from(self.num) => rax,
        in("rdi") usize::from(self.arg[0]),
        in("rsi") usize::from(self.arg[1]),
        inlateout("rdx") usize::from(self.arg[2]) => rdx,
        in("r10") usize::from(self.arg[3]),
        in("r8") usize::from(self.arg[4]),
        in("r9") usize::from(self.arg[5]),
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        );

        Reply {
            ret: [rax.into(), rdx.into()],
            err: Default::default(),
        }
    }
}

/// A reply
///
/// The `Reply` struct is the most minimal representation of the register context
/// needed for service replies from the hypervisor to the microkernel. An example
/// of such a reply would be the return value from a proxied system call.
///
/// Although most architectures collapse this to a single register value
/// with error numbers above `usize::max_value() - 4096`, `ppc64` uses
/// the `cr0.SO` flag to indicate error instead. Unfortunately, we also
/// can't use the built-in `Result` type for this, since its memory layout
/// is undefined. Therefore, we use this layout with conversions for `Result`.
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug)]
pub struct Reply {
    ret: [Register<usize>; 2],
    err: Register<usize>,
}

/// The result of a syscall
///
/// This is isomorphic with `Reply`, which is like `Result`, but has a stable
/// memory layout.
pub type Result = core::result::Result<[Register<usize>; 2], libc::c_int>;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl From<Result> for Reply {
    #[inline]
    fn from(value: Result) -> Self {
        match value {
            Ok(val) => Self {
                ret: val,
                err: Default::default(),
            },
            Err(val) => Self {
                ret: [(-val as usize).into(), Default::default()],
                err: Default::default(),
            },
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl From<Reply> for Result {
    #[inline]
    fn from(value: Reply) -> Self {
        let reg: usize = value.ret[0].into();
        if reg > -4096isize as usize {
            Err(-(reg as libc::c_int))
        } else {
            Ok(value.ret)
        }
    }
}

/// A message, which is either a request or a reply
#[repr(C)]
#[derive(Copy, Clone)]
pub union Message {
    /// A request
    pub req: Request,

    /// A reply
    pub rep: Reply,
}

/// The `Block` struct encloses the Message's register contexts but also provides
/// a data buffer used to store data that might be required to service the request.
/// For example, bytes that must be written out by the host could be stored in the
/// `Block`'s `buf` field. It is expected that the trusted microkernel has copied
/// the necessary data components into the `Block`'s `buf` field and has updated
/// the `msg` register context fields accordingly in the event those registers
/// must point to those data components within the `buf`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Block {
    /// The register contexts for this message; either a request or a reply.
    pub msg: Message,

    /// A buffer where any additional request components may be stored. For example,
    /// a series of bytes to be written out in a proxied `write` syscall.
    ///
    /// Note that this buffer size is *less than* a page, since the buffer shares
    /// space with the `Message` that describes it.
    buf: [u8; Block::buf_capacity()],
}

impl Default for Block {
    fn default() -> Self {
        Self {
            msg: Message {
                req: Request::default(),
            },
            buf: [0u8; Block::buf_capacity()],
        }
    }
}

impl Block {
    /// Returns the capacity of `Block.buf`
    pub const fn buf_capacity() -> usize {
        // At least MAX_UDP_PACKET_SIZE rounded up Page::size() alignment
        (MAX_UDP_PACKET_SIZE + size_of::<Message>() + Page::SIZE - 1) / Page::SIZE * Page::SIZE
            - size_of::<Message>()
    }

    /// Returns a Cursor for the Block
    #[allow(dead_code)]
    pub fn cursor(&mut self) -> Cursor {
        Cursor(&mut self.buf)
    }
}

/// Helper for allocation of untrusted memory in a Block.
pub struct Cursor<'a>(&'a mut [u8]);

/// Out of space
///
/// Indicates, that there is no space in the `Block` for the requested amount of bytes.
///
/// Because this crate is no_std, this error does not implement `std::error::Error`
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutOfSpace;

impl<'short, 'a: 'short> Cursor<'a> {
    /// Allocates an array, containing count number of T items. The result is uninitialized.
    pub fn alloc<T>(
        self,
        count: usize,
    ) -> core::result::Result<(Cursor<'a>, &'short mut [MaybeUninit<T>]), OutOfSpace> {
        let mid = {
            let (padding, data, _) = unsafe { self.0.align_to_mut::<MaybeUninit<T>>() };

            if data.len() < count {
                return Err(OutOfSpace);
            }

            padding.len() + size_of::<MaybeUninit<T>>() * count
        };

        let (data, next) = self.0.split_at_mut(mid);

        Ok((
            Cursor(next),
            unsafe { data.align_to_mut::<MaybeUninit<T>>() }.1,
        ))
    }

    /// Copies data from a slice into the cursor buffer using self.alloc().
    #[allow(dead_code)]
    pub fn copy_from_slice<T: 'a + Copy>(
        self,
        src: &[T],
    ) -> core::result::Result<(Cursor<'a>, &'short mut [T]), OutOfSpace> {
        let (c, dst) = self.alloc::<T>(src.len())?;

        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr() as _, src.len());
        }

        let dst = unsafe { &mut *(dst as *mut [MaybeUninit<T>] as *mut [T]) };

        Ok((c, dst))
    }

    /// Copies data from a cursor buffer into a slice advancing the cursor.
    ///
    /// # Parameters
    ///
    /// * `src_len`: the amount of elements, the cursor is advanced after copying
    /// * `dst`: the destination slice
    ///
    /// # Safety
    /// The caller has to ensure the `Cursor` contains valid data of the type
    /// of the destination slice.
    #[allow(dead_code)]
    pub unsafe fn copy_into_slice<T: 'a + Copy>(
        self,
        src_len: usize,
        dst: &mut [T],
    ) -> core::result::Result<Cursor<'a>, OutOfSpace> {
        self.copy_into_raw_parts(src_len, dst.as_mut_ptr(), dst.len())
    }

    /// Copies data from a raw slice pointer into the cursor buffer using self.alloc().
    ///
    /// The len argument is the number of **elements**, not the number of bytes.
    ///
    /// # Safety
    /// The caller has to ensure the source points to valid memory
    #[allow(dead_code)]
    pub unsafe fn copy_from_raw_parts<T: 'a + Copy>(
        self,
        src: *const T,
        src_len: usize,
    ) -> core::result::Result<(Cursor<'a>, *mut MaybeUninit<T>), OutOfSpace> {
        let (c, dst) = self.alloc::<T>(src_len)?;

        core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr() as *mut _, src_len);

        Ok((c, dst.as_mut_ptr()))
    }

    /// Copies data into a raw slice from the cursor buffer using self.alloc().
    ///
    /// The len argument is the number of **elements**, not the number of bytes.
    ///
    /// # Safety
    /// The caller has to ensure the destination points to valid memory
    #[allow(dead_code)]
    pub unsafe fn copy_into_raw_parts<T: 'a + Copy>(
        self,
        src_len: usize,
        dst: *mut T,
        dst_len: usize,
    ) -> core::result::Result<Cursor<'a>, OutOfSpace> {
        assert!(src_len >= dst_len);
        let (c, src) = self.alloc::<T>(src_len)?;

        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as _, dst_len);

        Ok(c)
    }

    /// Reads data from the the cursor buffer.
    ///
    /// # Safety
    /// The caller has to ensure the `Cursor` contains valid data.
    #[allow(dead_code)]
    pub unsafe fn read<T: 'a + Copy>(self) -> core::result::Result<(Cursor<'a>, T), OutOfSpace> {
        let (c, src) = self.alloc::<T>(1)?;

        Ok((c, src[0].as_ptr().read()))
    }

    /// Writes data into the cursor buffer.
    #[allow(dead_code)]
    pub fn write<T: 'a + Copy>(
        self,
        src: &T,
    ) -> core::result::Result<(Cursor<'a>, &'short mut T), OutOfSpace> {
        let (c, dst) = self.alloc::<T>(1)?;

        let dst = dst[0].as_mut_ptr();
        unsafe {
            core::ptr::write(dst, *src);
        }

        Ok((c, unsafe { &mut *dst }))
    }

    /// Overwrites a memory location with the value from the cursor buffer.
    ///
    /// # Safety
    /// * The caller has to ensure the destination pointer points to valid memory.
    /// * The pointer must be properly aligned.
    #[allow(dead_code)]
    pub unsafe fn copy_into<T: 'a + Copy>(
        self,
        dst: NonNull<T>,
    ) -> core::result::Result<Cursor<'a>, OutOfSpace> {
        let (c, src) = self.alloc::<T>(1)?;

        core::ptr::write(dst.as_ptr(), src[0].as_ptr().read());

        Ok(c)
    }
}
