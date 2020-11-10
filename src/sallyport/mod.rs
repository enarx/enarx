// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
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
        // FIXME: https://github.com/enarx/enarx-keepldr/issues/23
        let page_num = if cfg!(test) { 1 } else { 512 };
        page_num * Page::size() - size_of::<Message>()
    }

    /// Returns a Cursor for the Block
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

    /// Copies data from a slice into the cursor buffer using self.alloc().
    #[allow(dead_code)]
    pub fn copy_into_slice<T: Copy>(
        self,
        src_len: usize,
        dst: &mut [T],
        dst_len: usize,
    ) -> core::result::Result<Cursor<'a>, OutOfSpace> {
        assert!(src_len >= dst_len);
        assert!(dst.len() >= dst_len);

        let (c, src) = self.alloc::<T>(src_len)?;

        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr() as _, dst_len);
        }

        Ok(c)
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
    pub fn write<T: 'a + Copy>(self, src: &T) -> core::result::Result<Cursor<'a>, OutOfSpace> {
        let (c, dst) = self.alloc::<T>(1)?;

        unsafe {
            core::ptr::write(dst[0].as_mut_ptr(), *src);
        }

        Ok(c)
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
    fn block_size() {
        assert_eq!(size_of::<Block>(), Page::size());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn syscall() {
        // Test syscall failure, including bidirectional conversion.
        let req = request!(libc::SYS_close => -1isize);
        let rep = unsafe { req.syscall() };
        assert_eq!(rep, Err(libc::EBADF).into());
        assert_eq!(libc::EBADF, Result::from(rep).unwrap_err());

        // Test dup() success.
        let req = request!(libc::SYS_dup => 0usize);
        let rep = unsafe { req.syscall() };
        let dup_fd: usize = Result::from(rep).unwrap()[0].into();
        assert!(dup_fd > 0);

        // Test close() success.
        let req = request!(libc::SYS_close => dup_fd);
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
    fn cursor() {
        let mut block = Block::default();

        let c = block.cursor();
        assert!(c.alloc::<usize>(4096usize).is_err());

        let c = block.cursor();
        assert_eq!(c.alloc::<usize>(42usize).unwrap().1.len(), 42);

        let c = block.cursor();
        let (_c, slice) = c.copy_from_slice(&[87, 2, 3]).unwrap();
        assert_eq!(&slice, &[87, 2, 3]);
    }

    #[test]
    fn cursor_multiple_allocs() {
        let mut block = Block::default();

        let c = block.cursor();
        let (c, slab1) = c
            .copy_from_slice::<usize>(&[1, 2])
            .expect("allocate slab of 2 usize values for the first time");

        let (c, slab2) = c
            .copy_from_slice::<usize>(&[3, 4])
            .expect("allocate slab of 2 usize values for the second time");

        let (_c, slab3) = c
            .copy_from_slice::<usize>(&[5, 6])
            .expect("allocate slab of 2 usize values for the third time");

        assert_eq!(slab1, &[1, 2]);
        assert_eq!(slab2, &[3, 4]);
        assert_eq!(slab3, &[5, 6]);

        let c = block.cursor();
        let (_c, slab_all) = c
            .alloc::<usize>(6)
            .expect("re-allocate slab of 6 usize values already initialized");

        // Assume init
        let slab_all: &mut [usize] = unsafe { &mut *(slab_all as *mut _ as *mut [_]) };

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

    #[test]
    fn test_read_write() -> std::result::Result<(), OutOfSpace> {
        #[derive(Debug, Clone, Copy, PartialEq)]
        #[repr(C, align(64))]
        struct Test {
            a: u64,
            b: u64,
        }

        let mut block = Block::default();

        let c = block.cursor();

        let c = c.write(&Test { a: 1, b: 2 })?;
        let _c = c.write(&Test { a: 2, b: 3 })?;

        let c = block.cursor();

        let (c, test1) = unsafe { c.read::<Test>() }?;
        let (_, test2) = unsafe { c.read::<Test>() }?;

        assert_eq!(test1, Test { a: 1, b: 2 });
        assert_eq!(test2, Test { a: 2, b: 3 });

        Ok(())
    }

    #[test]
    fn copy_into_raw_parts() -> std::result::Result<(), OutOfSpace> {
        let mut block = Block::default();

        let c = block.cursor();
        let (c, slab1) = c
            .copy_from_slice::<usize>(&[1, 2])
            .expect("allocate slab of 2 usize values for the first time");

        let (c, slab2) = c
            .copy_from_slice::<usize>(&[3, 4])
            .expect("allocate slab of 2 usize values for the second time");

        let (_c, slab3) = c
            .copy_from_slice::<usize>(&[5, 6])
            .expect("allocate slab of 2 usize values for the third time");

        assert_eq!(slab1, &[1, 2]);
        assert_eq!(slab2, &[3, 4]);
        assert_eq!(slab3, &[5, 6]);

        let c = block.cursor();

        let mut slab_all = MaybeUninit::<[usize; 3]>::uninit();

        let c = unsafe { c.copy_into_raw_parts::<usize>(4, slab_all.as_mut_ptr() as _, 3)? };

        // Assume init
        let slab_all = unsafe { slab_all.assume_init() };

        assert_eq!(&slab_all, &[1, 2, 3]);

        let mut slab_all = MaybeUninit::<[usize; 2]>::uninit();

        unsafe {
            c.copy_into_raw_parts::<usize>(2, slab_all.as_mut_ptr() as _, 2)?;
        }

        // Assume init
        let slab_all = unsafe { slab_all.assume_init() };

        assert_eq!(&slab_all, &[5, 6]);

        Ok(())
    }
}
