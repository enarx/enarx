// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;
use primordial::{Page, Register};

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
        512 * Page::size() - size_of::<Message>()
    }

    /// Returns a Cursor for the Block
    pub fn cursor(&mut self) -> Cursor {
        Cursor(&mut self.buf)
    }
}

/// Helper for allocation of untrusted memory in a Block.
pub struct Cursor<'a>(&'a mut [u8]);

impl<'a> Cursor<'a> {
    /// Allocates an array, containing count number of T items. The result is uninitialized.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it returns an uninitialized array.
    pub unsafe fn alloc<T>(
        self,
        count: usize,
    ) -> core::result::Result<(Cursor<'a>, &'a mut [T]), ()> {
        let mid = {
            let (padding, data, _) = self.0.align_to_mut::<T>();

            if data.len() < count {
                return Err(());
            }

            padding.len() + size_of::<T>() * count
        };

        let (data, next) = self.0.split_at_mut(mid);

        Ok((Cursor(next), data.align_to_mut::<T>().1))
    }

    /// Copies data from a value into a slice using self.alloc().
    #[allow(dead_code)]
    pub fn copy_slice<T: Copy>(
        self,
        value: &[T],
    ) -> core::result::Result<(Cursor<'a>, &'a mut [T]), ()> {
        let (c, slice) = unsafe { self.alloc(value.len())? };
        slice.copy_from_slice(value);
        Ok((c, slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_size() {
        assert_eq!(size_of::<Request>(), size_of::<usize>() * 8);
    }

    #[test]
    fn rep_size() {
        assert_eq!(size_of::<Reply>(), size_of::<usize>() * 3);
    }

    #[test]
    fn msg_size() {
        assert_eq!(size_of::<Message>(), size_of::<usize>() * 8);
    }

    #[test]
    // FIXME this should not be ignored, this was applied as part
    // of a commit that must be reverted and implemented properly.
    #[ignore]
    fn block_size() {
        assert_eq!(size_of::<Block>(), Page::size());
    }

    #[test]
    fn syscall() {
        // Test syscall failure, including bidirectional conversion.
        let req = request!(libc::SYS_close => -1isize);
        let rep = unsafe { req.syscall() };
        assert_eq!(rep, Err(libc::EBADF).into());
        assert_eq!(libc::EBADF, Result::from(rep).unwrap_err());

        // Test dup() success.
        let req = request!(libc::SYS_dup => 0usize);
        let rep = unsafe { req.syscall() };
        let res = Result::from(rep).unwrap()[0].into();
        assert_eq!(3usize, res);

        // Test close() success.
        let req = request!(libc::SYS_close => 3usize);
        let rep = unsafe { req.syscall() };
        let res = Result::from(rep).unwrap()[0].into();
        assert_eq!(0usize, res);
    }

    #[test]
    fn request() {
        let req = request!(0 => 1, 2, 3, 4, 5, 6, 7, 8, 9);
        assert_eq!(req.num, Register::<usize>::from(0));
        assert_eq!(req.arg[0], Register::<usize>::from(1));
        assert_eq!(req.arg[1], Register::<usize>::from(2));
        assert_eq!(req.arg[2], Register::<usize>::from(3));
        assert_eq!(req.arg[3], Register::<usize>::from(4));
        assert_eq!(req.arg[4], Register::<usize>::from(5));
        assert_eq!(req.arg[5], Register::<usize>::from(6));
        assert_eq!(req.arg[6], Register::<usize>::from(7));

        let req = request!(0 => 1);
        assert_eq!(req.num, Register::<usize>::from(0));
        assert_eq!(req.arg[0], Register::<usize>::from(1));
        assert_eq!(req.arg[1], Register::<usize>::from(0));
        assert_eq!(req.arg[2], Register::<usize>::from(0));
        assert_eq!(req.arg[3], Register::<usize>::from(0));
        assert_eq!(req.arg[4], Register::<usize>::from(0));
        assert_eq!(req.arg[5], Register::<usize>::from(0));
        assert_eq!(req.arg[6], Register::<usize>::from(0));

        let req = request!(17);
        assert_eq!(req.num, Register::<usize>::from(17));
        assert_eq!(req.arg[0], Register::<usize>::from(0));
        assert_eq!(req.arg[1], Register::<usize>::from(0));
        assert_eq!(req.arg[2], Register::<usize>::from(0));
        assert_eq!(req.arg[3], Register::<usize>::from(0));
        assert_eq!(req.arg[4], Register::<usize>::from(0));
        assert_eq!(req.arg[5], Register::<usize>::from(0));
        assert_eq!(req.arg[6], Register::<usize>::from(0));
    }

    #[test]
    // FIXME this should not be ignored, this was applied as part
    // of a commit that must be reverted and implemented properly.
    #[ignore]
    fn cursor() {
        let mut block = Block::default();

        let c = block.cursor();
        assert!(unsafe { c.alloc::<usize>(4096usize).is_err() });

        let c = block.cursor();
        assert_eq!(unsafe { c.alloc::<usize>(42usize) }.unwrap().1.len(), 42);

        let c = block.cursor();
        let (_c, slice) = c.copy_slice(&[87, 2, 3]).unwrap();
        assert_eq!(&slice, &[87, 2, 3]);
    }

    #[test]
    // FIXME this should not be ignored, this was applied as part
    // of a commit that must be reverted and implemented properly.
    #[ignore]
    fn cursor_multiple_allocs() {
        let mut block = Block::default();

        let c = block.cursor();
        let (c, slab1) = unsafe {
            c.alloc::<usize>(2)
                .expect("allocate slab of 42 usize values for the first time")
        };
        slab1.copy_from_slice(&[1, 2]);

        let (c, slab2) = unsafe {
            c.alloc::<usize>(2)
                .expect("allocate slab of 42 usize values for the second time")
        };
        slab2.copy_from_slice(&[3, 4]);

        let (_c, slab3) = unsafe {
            c.alloc::<usize>(2)
                .expect("allocate slab of 42 usize values for the third time")
        };
        slab3.copy_from_slice(&[5, 6]);

        assert_eq!(slab1, &[1, 2]);
        assert_eq!(slab2, &[3, 4]);
        assert_eq!(slab3, &[5, 6]);

        let c = block.cursor();
        let (_c, slab_all) = unsafe {
            c.alloc::<usize>(6)
                .expect("re-allocate slab of 6 42 usize values already initialized")
        };
        assert_eq!(slab_all, &[1, 2, 3, 4, 5, 6]);

        // An attempt at re-using a mutable subslice from the first
        // cursor when aliasing with the second cursor will correctly
        // generate a compiler error.
        // slab3.copy_from_slice(&[1, 2]);

        // However, we can copy new values over using the second cursor
        // just fine.
        slab_all.copy_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(slab_all, &[0, 0, 0, 0, 0, 0]);
    }
}
