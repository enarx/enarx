// SPDX-License-Identifier: Apache-2.0

//! Create the initial stack frame to start an ELF binary on Linux
//!
//! # Examples
//!
//! ```rust
//! use crt0stack::{Builder, auxv::Entry};
//!
//! let mut stack = [1u8; 512];
//! let stack = stack.as_mut();
//!
//! let mut builder = Builder::new(stack);
//!
//! builder.push("/init").unwrap();
//! let mut builder = builder.done().unwrap();
//!
//! builder.push("HOME=/root").unwrap();
//! let mut builder = builder.done().unwrap();
//!
//! let auxv = [
//!     Entry::Gid(1000),
//!     Entry::Uid(1000),
//!     Entry::Platform("x86_64"),
//!     Entry::ExecFilename("/init"),
//! ];
//! auxv.iter().for_each(|e| builder.push(e).unwrap());
//!
//! let handle = builder.done().unwrap();
//! ```

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::integer_arithmetic)]

pub mod auxv;
pub use auxv::Entry;

use core::marker::PhantomData;
use core::mem::{self, size_of};
const STACK_ALIGNMENT: usize = 16;

const AT_NULL: usize = 0;
const AT_EXECFD: usize = 2;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;
const AT_BASE: usize = 7;
const AT_FLAGS: usize = 8;
const AT_ENTRY: usize = 9;
const AT_NOTELF: usize = 10;
const AT_UID: usize = 11;
const AT_EUID: usize = 12;
const AT_GID: usize = 13;
const AT_EGID: usize = 14;
const AT_CLKTCK: usize = 17;
const AT_PLATFORM: usize = 15;
const AT_HWCAP: usize = 16;
const AT_SECURE: usize = 23;
const AT_BASE_PLATFORM: usize = 24;
const AT_RANDOM: usize = 25;
const AT_HWCAP2: usize = 26;
const AT_EXECFN: usize = 31;
const AT_SYSINFO: usize = 32;
const AT_SYSINFO_EHDR: usize = 33;

/// Indicates too many arguments for `serialize`
///
/// Because this crate is no_std, it operates on a fixed sized byte slice.
/// This error indicates, that the arguments `arg`, `env` or `aux` exceed the
/// given slice size.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutOfSpace;

type Result<T> = core::result::Result<T, OutOfSpace>;

// Internal use only
trait Serializable {
    fn into_buf(&self, dst: &mut [u8]) -> Result<usize>;
}

impl Serializable for usize {
    #[inline]
    fn into_buf(&self, dst: &mut [u8]) -> Result<usize> {
        let (_prefix, dst, suffix) = unsafe { dst.align_to_mut::<usize>() };
        dst[dst.len().checked_sub(1).ok_or(OutOfSpace)?] = *self;
        let len = suffix.len();
        let len = len.checked_add(size_of::<usize>()).ok_or(OutOfSpace)?;
        Ok(len)
    }
}

impl Serializable for u8 {
    #[inline]
    fn into_buf(&self, dst: &mut [u8]) -> Result<usize> {
        dst[dst.len().checked_sub(1).ok_or(OutOfSpace)?] = *self;
        Ok(1)
    }
}

impl Serializable for &[u8] {
    #[inline]
    fn into_buf(&self, dst: &mut [u8]) -> Result<usize> {
        let start = dst.len().checked_sub(self.len()).ok_or(OutOfSpace)?;
        let end = dst.len();
        dst[start..end].copy_from_slice(self);
        Ok(self.len())
    }
}

/// State marker for Builder
pub enum Aux {}
/// State marker for Builder
pub enum Env {}
/// State marker for Builder
pub enum Arg {}

/// Handle for the stack
///
/// Retains the immutability and immovability of the stack buffer
pub struct Handle<'a>(&'a mut [u8], usize);
impl<'a> Handle<'a> {
    /// Returns a reference to the top of the prepared stack
    ///
    /// This reference can be used as the initial stack pointer
    /// to execute a Linux ELF binary.
    #[inline]
    pub fn start_ptr(&self) -> &'a () {
        unsafe { &*(&self.0[self.1] as *const u8 as *const ()) }
    }
}

/// Builder for the initial stack of a Linux ELF binary
///
/// # Examples
///
/// ```rust
/// use crt0stack::{Builder, auxv::Entry};
///
/// let mut stack = [1u8; 512];
/// let stack = stack.as_mut();
///
/// let mut builder = Builder::new(stack);
///
/// builder.push("/init").unwrap();
/// let mut builder = builder.done().unwrap();
///
/// builder.push("HOME=/root").unwrap();
/// let mut builder = builder.done().unwrap();
///
/// let auxv = [
///     Entry::Gid(1000),
///     Entry::Uid(1000),
///     Entry::Platform("x86_64"),
///     Entry::ExecFilename("/init"),
/// ];
/// auxv.iter().for_each(|e| builder.push(e).unwrap());
///
/// let handle = builder.done().unwrap();
/// ```
pub struct Builder<'a, T> {
    stack: &'a mut [u8],
    data: usize,  // Index to the bottom of the data section
    items: usize, // Index to the top of the items section
    state: PhantomData<T>,
}

impl<'a, T> Builder<'a, T> {
    // Serializes the input and saves it in the data section.
    // Returns a reference to the serialized input within the data section.
    #[inline]
    fn push_data(&mut self, val: impl Serializable) -> Result<*const ()> {
        let val_len = val.into_buf(&mut self.stack[..self.data])?;
        self.data = self.data.checked_sub(val_len).ok_or(OutOfSpace)?;
        if self.data <= self.items {
            Err(OutOfSpace)
        } else {
            Ok(&self.stack[self.data] as *const u8 as *const ())
        }
    }

    // Serializes the input and saves it in the item section.
    #[inline]
    fn push_item(&mut self, val: usize) -> Result<()> {
        let (prefix, dst, _suffix) = {
            let start = self.items;
            let end = self.data;
            unsafe { self.stack[start..end].align_to_mut::<usize>() }
        };
        if dst.is_empty() {
            return Err(OutOfSpace);
        }
        dst[0] = val;
        let len = prefix.len();
        let len = len.checked_add(size_of::<usize>()).ok_or(OutOfSpace)?;
        self.items = self.items.checked_add(len).ok_or(OutOfSpace)?;

        if self.data <= self.items {
            Err(OutOfSpace)
        } else {
            Ok(())
        }
    }
}

impl<'a> Builder<'a, Arg> {
    /// Create a new Builder for the stack
    ///
    /// Needs a sufficiently large byte slice.
    #[inline]
    pub fn new(stack: &'a mut [u8]) -> Self {
        let len = stack.len();
        Self {
            stack,
            data: len,
            items: size_of::<usize>(),
            state: PhantomData,
        }
    }

    /// Push a new `argv` argument
    #[inline]
    pub fn push(&mut self, arg: &str) -> Result<()> {
        self.push_data(0u8)?; // c-str zero byte
        let p = self.push_data(arg.as_bytes())?;
        self.push_item(p as usize)
    }

    /// Advance the Builder to the next step
    #[inline]
    pub fn done(mut self) -> Result<Builder<'a, Env>> {
        // last argv is NULL
        self.push_item(0usize)?;

        // Store argc at the beginning
        let (prefix, dst, _suffix) = {
            let start = 0;
            let end = self.data;
            unsafe { self.stack[start..end].align_to_mut::<usize>() }
        };
        if dst.is_empty() {
            return Err(OutOfSpace);
        }

        // Calculate argc = (self.items - prefix.len()) / size_of::<usize> - 2
        dst[0] = self.items.checked_sub(prefix.len()).ok_or(OutOfSpace)?;
        dst[0] = dst[0].checked_div(size_of::<usize>()).ok_or(OutOfSpace)?;
        dst[0] = dst[0].checked_sub(2).ok_or(OutOfSpace)?;

        Ok(Builder {
            stack: self.stack,
            data: self.data,
            items: self.items,
            state: PhantomData,
        })
    }
}

impl<'a> Builder<'a, Env> {
    /// Add a new environment variable string
    #[inline]
    pub fn push(&mut self, env: &str) -> Result<()> {
        self.push_data(0u8)?; // c-str zero byte
        let p = self.push_data(env.as_bytes())?;
        self.push_item(p as usize)
    }

    /// Advance the Build to the next step
    #[inline]
    pub fn done(mut self) -> Result<Builder<'a, Aux>> {
        // last environ is NULL
        self.push_item(0usize)?;
        Ok(Builder {
            stack: self.stack,
            data: self.data,
            items: self.items,
            state: PhantomData,
        })
    }
}

impl<'a> Builder<'a, Aux> {
    /// Add a new auxv::Entry
    #[inline]
    pub fn push(&mut self, entry: &auxv::Entry) -> Result<()> {
        let (key, value): (usize, usize) = match *entry {
            Entry::Platform(x) => {
                self.push_data(0u8)?;
                (AT_PLATFORM, self.push_data(x.as_bytes())? as _)
            }
            Entry::BasePlatform(x) => {
                self.push_data(0u8)?;
                (AT_BASE_PLATFORM, self.push_data(x.as_bytes())? as _)
            }
            Entry::ExecFilename(x) => {
                self.push_data(0u8)?;
                (AT_EXECFN, self.push_data(x.as_bytes())? as _)
            }
            Entry::Random(x) => (AT_RANDOM, self.push_data(&x[..])? as _),
            Entry::ExecFd(v) => (AT_EXECFD, v),
            Entry::PHdr(v) => (AT_PHDR, v),
            Entry::PHent(v) => (AT_PHENT, v),
            Entry::PHnum(v) => (AT_PHNUM, v),
            Entry::PageSize(v) => (AT_PAGESZ, v),
            Entry::Base(v) => (AT_BASE, v),
            Entry::Flags(v) => (AT_FLAGS, v),
            Entry::Entry(v) => (AT_ENTRY, v),
            Entry::NotElf(v) => (AT_NOTELF, if v { 1 } else { 0 }),
            Entry::Uid(v) => (AT_UID, v),
            Entry::EUid(v) => (AT_EUID, v),
            Entry::Gid(v) => (AT_GID, v),
            Entry::EGid(v) => (AT_EGID, v),
            Entry::HwCap(v) => (AT_HWCAP, v),
            Entry::ClockTick(v) => (AT_CLKTCK, v),
            Entry::Secure(v) => (AT_SECURE, if v { 1 } else { 0 }),
            Entry::HwCap2(v) => (AT_HWCAP2, v),
            Entry::SysInfo(v) => (AT_SYSINFO, v),
            Entry::SysInfoEHdr(v) => (AT_SYSINFO_EHDR, v),
        };
        self.push_item(key)?;
        self.push_item(value)?;
        Ok(())
    }

    /// Finish the Builder and get the `Handle`
    #[inline]
    pub fn done(mut self) -> Result<Handle<'a>> {
        self.push_item(AT_NULL)?;
        self.push_item(0)?;

        let start_idx = {
            // at the end, copy the items of the item section from the bottom to the top of the stack

            /*

            +------------------------+  len           +------------------------+  len
            |                        |                |                        |
            |          data          |                |          data          |
            |                        |                |                        |
            +------------------------+                +------------------------+
            |                        |                |                        |
            |                        |                |         items          |
            |                        |  +---------->  |                        |
            |                        |                +------------------------+ <---+ stack pointer
            +------------------------+                |                        |
            |                        |                |                        |
            |         items          |                |                        |
            |                        |                |                        |
            +------------------------+  0             +------------------------+  0

            */

            // align down the destination pointer
            let dst_start_idx = self.data.checked_sub(self.items).ok_or(OutOfSpace)?;

            #[allow(clippy::integer_arithmetic)]
            let align_offset = (&self.stack[dst_start_idx] as *const u8 as usize) % STACK_ALIGNMENT;

            let dst_start_idx = dst_start_idx.checked_sub(align_offset).ok_or(OutOfSpace)?;

            // Align the source start index
            #[allow(clippy::integer_arithmetic)]
            let src_start_idx = self.items % size_of::<usize>();

            self.stack
                .copy_within(src_start_idx..self.items, dst_start_idx);

            dst_start_idx
        };
        Ok(Handle(self.stack, start_idx))
    }
}

// Convert a usize (pointer) to a string.
#[allow(clippy::integer_arithmetic)]
unsafe fn u2s<'a>(ptr: usize) -> core::result::Result<&'a str, core::str::Utf8Error> {
    let ptr = ptr as *const u8;

    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }

    let buf = core::slice::from_raw_parts(ptr, len);
    core::str::from_utf8(buf)
}

/// Reader for the initial stack of a Linux ELF binary
pub struct Reader<'a, T> {
    stack: *const usize,
    state: PhantomData<&'a T>,
}

impl<'a> Reader<'a, ()> {
    /// Create a new Reader from a pointer to the stack
    ///
    /// # Safety
    ///
    /// This function creates a reader by taking a reference to a hopefully well-crafted
    /// crt0 stack. We have no way to validate that this is the case. If the pointer
    /// points to some other kind of data, there will likely be crashes. So be sure you
    /// get this right.
    #[inline]
    pub unsafe fn from_stack(stack: &'a ()) -> Self {
        Self {
            stack: stack as *const _ as _,
            state: PhantomData,
        }
    }

    /// Returns the number of arguments
    #[inline]
    pub fn count(&self) -> usize {
        unsafe { *self.stack }
    }

    /// Starts parsing the arguments
    #[inline]
    pub fn done(self) -> Reader<'a, Arg> {
        Reader {
            stack: unsafe { self.stack.add(1) },
            state: PhantomData,
        }
    }
}

impl<'a> Iterator for Reader<'a, Arg> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if unsafe { *self.stack } == 0 {
            return None;
        }

        match unsafe { u2s(*self.stack) } {
            Ok(s) => {
                self.stack = unsafe { self.stack.add(1) };
                Some(s)
            }
            Err(_) => None,
        }
    }
}

impl<'a> Reader<'a, Arg> {
    /// Rewind to the start of this section
    #[inline]
    #[allow(clippy::integer_arithmetic)]
    pub fn rewind(&mut self) {
        // Go to the end of this section.
        while unsafe { *self.stack } != 0 {
            self.stack = unsafe { self.stack.add(1) };
        }

        // Decrement the pointer until we reach the count.
        let mut len = 0;
        self.stack = unsafe { self.stack.sub(1) };
        while unsafe { *self.stack } != len {
            self.stack = unsafe { self.stack.sub(1) };
            len += 1;
        }

        // Increment once
        self.stack = unsafe { self.stack.add(1) };
    }

    /// Returns parsing to the argument count section
    #[inline]
    pub fn prev(mut self) -> Reader<'a, ()> {
        self.rewind();

        Reader {
            stack: unsafe { self.stack.sub(1) },
            state: PhantomData,
        }
    }

    /// Starts parsing the environment
    #[inline]
    pub fn done(mut self) -> Reader<'a, Env> {
        while unsafe { *self.stack } != 0 {
            self.stack = unsafe { self.stack.add(1) };
        }

        Reader {
            stack: unsafe { self.stack.add(1) },
            state: PhantomData,
        }
    }
}

impl<'a> Iterator for Reader<'a, Env> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if unsafe { *self.stack } == 0 {
            return None;
        }

        match unsafe { u2s(*self.stack) } {
            Ok(s) => {
                self.stack = unsafe { self.stack.add(1) };
                Some(s)
            }
            Err(_) => None,
        }
    }
}

impl<'a> Reader<'a, Env> {
    /// Create a new Reader from the POSIX `environ` pointer
    #[inline]
    #[cfg(any(test, feature = "std"))]
    pub fn from_environ() -> Self {
        extern "C" {
            static environ: *const usize;
        }

        Reader {
            stack: unsafe { environ },
            state: PhantomData,
        }
    }

    /// Rewind to the start of this section
    #[inline]
    pub fn rewind(&mut self) {
        self.stack = unsafe { self.stack.sub(1) };

        while unsafe { *self.stack } != 0 {
            self.stack = unsafe { self.stack.sub(1) };
        }

        self.stack = unsafe { self.stack.add(1) };
    }

    /// Returns parsing to the start of the argument section
    #[inline]
    pub fn prev(mut self) -> Reader<'a, Arg> {
        self.rewind();

        let mut prev: Reader<'a, Arg> = Reader {
            stack: unsafe { self.stack.sub(1) },
            state: PhantomData,
        };

        prev.rewind();
        prev
    }

    /// Starts parsing the auxiliary vector
    #[inline]
    pub fn done(mut self) -> Reader<'a, Aux> {
        while unsafe { *self.stack } != 0 {
            self.stack = unsafe { self.stack.add(1) };
        }

        Reader {
            stack: unsafe { self.stack.add(1) },
            state: PhantomData,
        }
    }
}

impl<'a> Iterator for Reader<'a, Aux> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let val = unsafe { *self.stack.add(1) };

        let entry = match unsafe { mem::transmute(*self.stack) } {
            AT_NULL => return None,
            AT_EXECFD => Entry::ExecFd(val),
            AT_PHDR => Entry::PHdr(val),
            AT_PHENT => Entry::PHent(val),
            AT_PHNUM => Entry::PHnum(val),
            AT_PAGESZ => Entry::PageSize(val),
            AT_BASE => Entry::Base(val),
            AT_FLAGS => Entry::Flags(val),
            AT_ENTRY => Entry::Entry(val),
            AT_NOTELF => Entry::NotElf(val != 0),
            AT_UID => Entry::Uid(val),
            AT_EUID => Entry::EUid(val),
            AT_GID => Entry::Gid(val),
            AT_EGID => Entry::EGid(val),
            AT_PLATFORM => Entry::Platform(unsafe { u2s(val).ok()? }),
            AT_HWCAP => Entry::HwCap(val),
            AT_CLKTCK => Entry::ClockTick(val),
            AT_SECURE => Entry::Secure(val != 0),
            AT_BASE_PLATFORM => Entry::BasePlatform(unsafe { u2s(val).ok()? }),
            AT_RANDOM => Entry::Random(unsafe { *(val as *const [u8; 16]) }),
            AT_HWCAP2 => Entry::HwCap2(val),
            AT_EXECFN => Entry::ExecFilename(unsafe { u2s(val).ok()? }),

            #[cfg(target_arch = "x86")]
            AT_SYSINFO => Entry::SysInfo(val),

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            AT_SYSINFO_EHDR => Entry::SysInfoEHdr(val),

            _ => {
                return {
                    self.stack = unsafe { self.stack.add(2) };
                    self.next()
                }
            }
        };

        self.stack = unsafe { self.stack.add(2) };
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stack<'a> {
        idx: usize,
        stack: &'a mut [u8],
    }

    impl<'a> Stack<'a> {
        #[inline(always)]
        fn new(slice: &'a mut [u8]) -> Self {
            Self {
                idx: slice.len(),
                stack: slice,
            }
        }
        #[inline(always)]
        fn push(&mut self, val: impl Serializable) {
            self.idx -= val.into_buf(&mut self.stack[..self.idx]).unwrap();
        }

        #[inline(always)]
        fn pop_l<T: Sized + Copy>(&mut self) -> T {
            let mut val = mem::MaybeUninit::<T>::uninit();
            let size = size_of::<T>();
            assert!((self.idx + size) <= self.stack.len(), "Stack underflow");

            unsafe {
                let ptr: *mut T = &mut self.stack[self.idx] as *mut u8 as _;
                val.as_mut_ptr().write(ptr.read());
            }
            self.idx += size;
            unsafe { val.assume_init() }
        }

        #[inline(always)]
        fn pop_slice<T: Sized + Copy>(&mut self, val: &mut [T]) {
            let size = size_of::<T>() * val.len();
            assert!((self.idx + size) <= self.stack.len(), "Stack underflow");

            unsafe {
                let ptr: *mut T = &mut self.stack[self.idx] as *mut u8 as _;
                core::ptr::copy_nonoverlapping(ptr, val.as_mut_ptr(), val.len());
            }
            self.idx += size;
        }
    }

    #[test]
    fn stack() {
        let mut stack = [1u8; 16];
        let stack = stack.as_mut();
        let mut sp = Stack::new(stack);
        sp.push(16usize);
        sp.push(&[1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8][..]);
        assert_eq!(
            sp.stack,
            &mut [1, 2, 3, 4, 5, 6, 7, 8, 16, 0, 0, 0, 0, 0, 0, 0,]
        );
    }

    #[test]
    fn stack_slice() {
        let mut stack = [1u8; 16];
        let stack = stack.as_mut();
        let mut sp = Stack::new(stack);
        sp.push(&b"Hello World"[..]);
        assert_eq!(
            sp.stack,
            &mut [1, 1, 1, 1, 1, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
        );
    }

    #[test]
    fn stack_unaligned() {
        let mut stack = [0xFFu8; 24];
        let stack = stack.as_mut();
        let mut sp = Stack::new(stack);
        sp.push(1u8);
        sp.push(2usize);
        sp.push(3u8);
        assert_eq!(
            sp.stack,
            &mut [
                255, 255, 255, 255, 255, 255, 255, 3, // 3. u3
                2, 0, 0, 0, 0, 0, 0, 0, // 2. u64
                255, 255, 255, 255, 255, 255, 255, 1 // 1. u8
            ]
        );
    }

    #[test]
    fn stack_pop() {
        let mut stack = [1u8; 16];
        let stack = stack.as_mut();
        {
            let mut sp = Stack::new(stack);
            sp.push(16usize);
            sp.push(&[1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8][..]);
            let mut sliceval = [0u8; 8];
            sp.pop_slice(&mut sliceval);
            assert_eq!(sliceval, [1, 2, 3, 4, 5, 6, 7, 8]);
            let lval: u64 = sp.pop_l();
            assert_eq!(lval, 16u64);
        }
    }

    #[test]
    #[should_panic]
    fn stack_underflow() {
        let mut stack = [1u8; 16];
        let stack = stack.as_mut();
        {
            let mut sp = Stack::new(stack);
            sp.push(16usize);
            sp.push(&[1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8][..]);
            let mut sliceval = [0u8; 8];
            sp.pop_slice(&mut sliceval);
            assert_eq!(sliceval, [1, 2, 3, 4, 5, 6, 7, 8]);
            let lval: u64 = sp.pop_l();
            assert_eq!(lval, 16u64);
            let lval_u8: u8 = sp.pop_l();
            eprintln!("{}", lval_u8);
        }
    }

    #[test]
    #[should_panic]
    fn stack_overflow() {
        let mut stack = [1u8; 16];
        let stack = stack.as_mut();
        {
            let mut sp = Stack::new(stack);
            sp.push(16usize);
            sp.push(16usize);
            sp.push(16usize);
        }
    }

    #[test]
    fn builder() {
        use std::ffi::CStr;

        let prog = "/init";

        let auxv = [
            Entry::Random([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Entry::Gid(1000),
            Entry::Uid(1000),
            Entry::Platform("x86_64"),
            Entry::ExecFilename(prog),
        ];

        let mut stack = [1u8; 512];
        let stack = stack.as_mut();

        let mut builder = Builder::new(stack);
        builder.push(prog).unwrap();
        let mut builder = builder.done().unwrap();
        builder.push("HOME=/root").unwrap();
        let mut builder = builder.done().unwrap();
        auxv.iter().for_each(|e| builder.push(e).unwrap());
        let handle = builder.done().unwrap();

        let spindex: usize = handle.1;
        let mut prep_stack = Stack {
            stack: &mut handle.0[spindex..],
            idx: 0,
        };
        let argc: u64 = prep_stack.pop_l();
        assert_eq!(argc, 1);

        let arg: *const std::os::raw::c_char = prep_stack.pop_l();
        let cstr = unsafe { CStr::from_ptr(arg) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, prog);
        let arg: *const std::os::raw::c_char = prep_stack.pop_l();
        assert_eq!(arg, core::ptr::null());

        let arg: *const std::os::raw::c_char = prep_stack.pop_l();
        let cstr = unsafe { CStr::from_ptr(arg) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, "HOME=/root");
        let arg: *const std::os::raw::c_char = prep_stack.pop_l();
        assert_eq!(arg, core::ptr::null());

        let key: usize = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, AT_RANDOM);
        let s: &[u8; 16] = unsafe { mem::transmute(value) };
        assert_eq!(s, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let key: usize = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, AT_GID);
        assert_eq!(value, 1000);

        let key: usize = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, AT_UID);
        assert_eq!(value, 1000);

        let key: usize = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, AT_PLATFORM);
        let cstr = unsafe { CStr::from_ptr(value as *const u8 as _) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, "x86_64");

        let key: usize = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, AT_EXECFN);
        let cstr = unsafe { CStr::from_ptr(value as _) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, prog);

        let key: usize = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, AT_NULL);
        assert_eq!(value, 0);
    }

    #[test]
    fn reader() {
        let mut stack = [0u8; 512];

        let mut builder = Builder::new(&mut stack);
        builder.push("foo").unwrap();
        builder.push("bar").unwrap();
        builder.push("baz").unwrap();

        let mut builder = builder.done().unwrap();
        builder.push("FOO=foo").unwrap();
        builder.push("BAR=bar").unwrap();
        builder.push("BAZ=baz").unwrap();

        let mut builder = builder.done().unwrap();
        builder.push(&Entry::Random([255u8; 16])).unwrap();
        builder.push(&Entry::Platform("foo")).unwrap();
        builder.push(&Entry::Secure(true)).unwrap();
        builder.push(&Entry::Uid(1234)).unwrap();

        let handle = builder.done().unwrap();

        let reader = unsafe { Reader::from_stack(handle.start_ptr()) };
        assert_eq!(reader.count(), 3);

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some("foo"));
        assert_eq!(reader.next(), Some("bar"));
        assert_eq!(reader.next(), Some("baz"));
        assert_eq!(reader.next(), None);

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some("FOO=foo"));
        assert_eq!(reader.next(), Some("BAR=bar"));
        assert_eq!(reader.next(), Some("BAZ=baz"));
        assert_eq!(reader.next(), None);

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some(Entry::Random([255u8; 16])));
        assert_eq!(reader.next(), Some(Entry::Platform("foo")));
        assert_eq!(reader.next(), Some(Entry::Secure(true)));
        assert_eq!(reader.next(), Some(Entry::Uid(1234)));
        assert_eq!(reader.next(), None);
    }

    #[test]
    fn reader_skip() {
        let mut stack = [0u8; 512];

        let mut builder = Builder::new(&mut stack);
        builder.push("foo").unwrap();
        builder.push("bar").unwrap();
        builder.push("baz").unwrap();

        let mut builder = builder.done().unwrap();
        builder.push("FOO=foo").unwrap();
        builder.push("BAR=bar").unwrap();
        builder.push("BAZ=baz").unwrap();

        let mut builder = builder.done().unwrap();
        builder.push(&Entry::Random([255u8; 16])).unwrap();
        builder.push(&Entry::Platform("foo")).unwrap();
        builder.push(&Entry::Secure(true)).unwrap();
        builder.push(&Entry::Uid(1234)).unwrap();

        let handle = builder.done().unwrap();

        let reader = unsafe { Reader::from_stack(handle.start_ptr()) };
        assert_eq!(reader.count(), 3);

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some("foo"));
        // skip additional values

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some("FOO=foo"));
        // skip additional values

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some(Entry::Random([255u8; 16])));
        assert_eq!(reader.next(), Some(Entry::Platform("foo")));
        assert_eq!(reader.next(), Some(Entry::Secure(true)));
        assert_eq!(reader.next(), Some(Entry::Uid(1234)));
        assert_eq!(reader.next(), None);
    }

    #[test]
    fn reader_real() {
        let reader = Reader::from_environ().prev().prev();
        assert_eq!(reader.count(), std::env::args().count());

        let mut reader = reader.done();
        for arg in &mut reader {
            eprintln!("arg: {:?}", arg);
        }

        let mut reader = reader.done();
        for env in &mut reader {
            println!("env: {:?}", env);
        }

        let mut reader = reader.done();
        for aux in &mut reader {
            println!("aux: {:?}", aux);
        }
    }

    #[test]
    fn reader_unknown() {
        let stack = [
            0usize,  // argc
            0usize,  // arg terminator
            0usize,  // env terminator
            AT_UID,  // UID
            1234,    // UID
            0xAAAA,  // unknown
            0xAAAA,  // unknown
            AT_GID,  // GID
            1234,    // GID
            AT_NULL, // terminator
            0usize,  // terminator
        ];

        let reader = unsafe { Reader::from_stack(&*(stack.as_ptr() as *const ())) };
        assert_eq!(reader.count(), 0);

        let mut reader = reader.done();
        assert_eq!(reader.next(), None); // terminator
        assert_eq!(reader.next(), None); // don't overrun

        let mut reader = reader.done();
        assert_eq!(reader.next(), None); // terminator
        assert_eq!(reader.next(), None); // don't overrun

        let mut reader = reader.done();
        assert_eq!(reader.next(), Some(Entry::Uid(1234)));
        assert_eq!(reader.next(), Some(Entry::Gid(1234))); // skip unknown...
        assert_eq!(reader.next(), None); // terminator
        assert_eq!(reader.next(), None); // don't overrun
    }

    #[test]
    fn crt0_stack_alignment() {
        // Prepare the crt0 stack.
        #[repr(C, align(32))]
        struct Aligned<T>(T);

        let mut aligned = Aligned([0u8; 1024]);
        let mut error = false;
        for i in 0..32 {
            let mut builder = Builder::new(&mut aligned.0[i..]);
            builder.push("arg").unwrap();
            // Set the environment
            let mut builder = builder.done().unwrap();
            builder.push("LANG=C").unwrap();

            // Set the aux vector
            let mut builder = builder.done().unwrap();
            builder.push(&Entry::ExecFilename("/init")).unwrap();
            builder.push(&Entry::Platform("x86_64")).unwrap();
            builder.push(&Entry::Uid(1000)).unwrap();
            builder.push(&Entry::EUid(1000)).unwrap();
            builder.push(&Entry::Gid(1000)).unwrap();
            builder.push(&Entry::EGid(1000)).unwrap();
            builder.push(&Entry::PageSize(4096)).unwrap();
            builder.push(&Entry::Secure(false)).unwrap();
            builder.push(&Entry::ClockTick(100)).unwrap();
            builder.push(&Entry::Flags(0)).unwrap(); // TODO: https://github.com/enarx/enarx/issues/386
            builder.push(&Entry::HwCap(0)).unwrap(); // TODO: https://github.com/enarx/enarx/issues/386
            builder.push(&Entry::HwCap2(0)).unwrap(); // TODO: https://github.com/enarx/enarx/issues/386
            builder.push(&Entry::Random([0u8; 16])).unwrap();

            let handle = builder.done().unwrap();
            let alignment = (handle.start_ptr() as *const () as usize) % STACK_ALIGNMENT;
            eprintln!("offset: {}, alignment: {}", i, alignment);
            error |= alignment != 0;
        }
        assert!(!error);
    }
}
