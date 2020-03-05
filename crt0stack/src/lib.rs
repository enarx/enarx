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

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod auxv;
pub use auxv::Entry;

use auxv::Key;
use core::marker::PhantomData;

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
        if dst.is_empty() {
            return Err(OutOfSpace);
        }
        dst[dst.len() - 1] = *self;
        Ok(suffix.len() + core::mem::size_of::<usize>())
    }
}

impl Serializable for u8 {
    #[inline]
    fn into_buf(&self, dst: &mut [u8]) -> Result<usize> {
        if dst.is_empty() {
            return Err(OutOfSpace);
        }
        dst[dst.len() - 1] = *self;
        Ok(1)
    }
}

impl Serializable for &[u8] {
    #[inline]
    fn into_buf(&self, dst: &mut [u8]) -> Result<usize> {
        if dst.len() < self.len() {
            return Err(OutOfSpace);
        }
        let start = dst.len() - self.len();
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
        self.data -= val.into_buf(&mut self.stack[..self.data])?;
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
        self.items += prefix.len() + core::mem::size_of::<usize>();
        Ok(())
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
            items: core::mem::size_of::<usize>(),
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
        dst[0] = ((self.items - prefix.len()) / core::mem::size_of::<usize>()) - 2; // argc

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
        let (key, value): (Key, usize) = match *entry {
            Entry::Platform(x) => {
                self.push_data(0u8)?;
                (Key::PLATFORM, self.push_data(x.as_bytes())? as _)
            }
            Entry::BasePlatform(x) => {
                self.push_data(0u8)?;
                (Key::BASE_PLATFORM, self.push_data(x.as_bytes())? as _)
            }
            Entry::ExecFilename(x) => {
                self.push_data(0u8)?;
                (Key::EXECFN, self.push_data(x.as_bytes())? as _)
            }
            Entry::Random(x) => (Key::RANDOM, self.push_data(&x[..])? as _),
            Entry::ExecFd(v) => (Key::EXECFD, v),
            Entry::PHdr(v) => (Key::PHDR, v),
            Entry::PHent(v) => (Key::PHENT, v),
            Entry::PHnum(v) => (Key::PHNUM, v),
            Entry::PageSize(v) => (Key::PAGESZ, v),
            Entry::Base(v) => (Key::BASE, v),
            Entry::Flags(v) => (Key::FLAGS, v),
            Entry::Entry(v) => (Key::ENTRY, v),
            Entry::NotElf(v) => (Key::NOTELF, if v { 1 } else { 0 }),
            Entry::Uid(v) => (Key::UID, v),
            Entry::EUid(v) => (Key::EUID, v),
            Entry::Gid(v) => (Key::GID, v),
            Entry::EGid(v) => (Key::EGID, v),
            Entry::HWCap(v) => (Key::HWCAP, v),
            Entry::ClockTick(v) => (Key::CLKTCK, v),
            Entry::Secure(v) => (Key::SECURE, if v { 1 } else { 0 }),
            Entry::HWCap2(v) => (Key::HWCAP2, v),

            #[cfg(target_arch = "x86")]
            Entry::SysInfo(v) => (Key::SYSINFO, v),

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Entry::SysInfoEHdr(v) => (Key::SYSINFO_EHDR, v),
        };
        self.push_item(key.into())?;
        self.push_item(value)?;
        Ok(())
    }

    /// Finish the Builder and get the `Handle`
    #[inline]
    pub fn done(mut self) -> Result<Handle<'a>> {
        self.push_item(Key::NULL.into())?;
        self.push_item(0)?;

        let start_idx = {
            // at the end, copy the items of the item section from the bottom to the top of the stack
            let (bottom, top) = self.stack.split_at_mut(self.items);

            let (_prefix, src, _suffix) = unsafe { bottom.align_to_mut::<usize>() };

            let (prefix, dst, _suffix) = {
                let end = self.data - self.items;
                unsafe { top[0..end].align_to_mut::<usize>() }
            };
            let start = dst.len() - src.len();
            let end = dst.len();
            dst[start..end].copy_from_slice(src);
            self.items + (prefix.len() + start) * core::mem::size_of::<usize>()
        };
        Ok(Handle(self.stack, start_idx))
    }
}

// Convert a usize (pointer) to a string.
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
    index: usize,
    state: PhantomData<&'a T>,
}

impl<'a> Reader<'a, ()> {
    /// Create a new Reader for the stack
    ///
    /// # Safety
    ///
    /// This function creates a reader by taking a reference to a hopefully well-crafted
    /// crt0 stack. We have no way to validate that this is the case. If the pointer
    /// points to some other kind of data, there will likely be crashes. So be sure you
    /// get this right.
    #[inline]
    pub unsafe fn new(stack: &'a ()) -> Self {
        Self {
            stack: stack as *const _ as _,
            index: 0,
            state: PhantomData,
        }
    }

    /// Returns the number of arguments
    #[inline]
    pub fn count(&self) -> usize {
        unsafe { *self.stack.add(self.index) }
    }

    /// Starts parsing the arguments
    #[inline]
    pub fn done(self) -> Reader<'a, Arg> {
        Reader {
            stack: self.stack,
            index: 1,
            state: PhantomData,
        }
    }
}

impl<'a> Iterator for Reader<'a, Arg> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if unsafe { *self.stack.add(self.index) } == 0 {
            return None;
        }

        match unsafe { u2s(*self.stack.add(self.index)) } {
            Ok(s) => {
                self.index += 1;
                Some(s)
            }
            Err(_) => None,
        }
    }
}

impl<'a> Reader<'a, Arg> {
    /// Starts parsing the environment
    #[inline]
    pub fn done(mut self) -> Reader<'a, Env> {
        while unsafe { *self.stack.add(self.index) } != 0 {
            self.index += 1;
        }

        Reader {
            stack: self.stack,
            index: self.index + 1,
            state: PhantomData,
        }
    }
}

impl<'a> Iterator for Reader<'a, Env> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if unsafe { *self.stack.add(self.index) } == 0 {
            return None;
        }

        match unsafe { u2s(*self.stack.add(self.index)) } {
            Ok(s) => {
                self.index += 1;
                Some(s)
            }
            Err(_) => None,
        }
    }
}

impl<'a> Reader<'a, Env> {
    /// Starts parsing the auxiliary vector
    #[inline]
    pub fn done(mut self) -> Reader<'a, Aux> {
        while unsafe { *self.stack.add(self.index) } != 0 {
            self.index += 1;
        }

        Reader {
            stack: self.stack,
            index: self.index + 1,
            state: PhantomData,
        }
    }
}

impl<'a> Iterator for Reader<'a, Aux> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let val = unsafe { *self.stack.add(self.index + 1) };

        let entry = match unsafe { core::mem::transmute(*self.stack.add(self.index)) } {
            Key::NULL => return None,
            Key::EXECFD => Entry::ExecFd(val),
            Key::PHDR => Entry::PHdr(val),
            Key::PHENT => Entry::PHent(val),
            Key::PHNUM => Entry::PHnum(val),
            Key::PAGESZ => Entry::PageSize(val),
            Key::BASE => Entry::Base(val),
            Key::FLAGS => Entry::Flags(val),
            Key::ENTRY => Entry::Entry(val),
            Key::NOTELF => Entry::NotElf(val != 0),
            Key::UID => Entry::Uid(val),
            Key::EUID => Entry::EUid(val),
            Key::GID => Entry::Gid(val),
            Key::EGID => Entry::EGid(val),
            Key::PLATFORM => Entry::Platform(unsafe { u2s(val).ok()? }),
            Key::HWCAP => Entry::HWCap(val),
            Key::CLKTCK => Entry::ClockTick(val),
            Key::SECURE => Entry::Secure(val != 0),
            Key::BASE_PLATFORM => Entry::BasePlatform(unsafe { u2s(val).ok()? }),
            Key::RANDOM => Entry::Random(unsafe { *(val as *const [u8; 16]) }),
            Key::HWCAP2 => Entry::HWCap2(val),
            Key::EXECFN => Entry::ExecFilename(unsafe { u2s(val).ok()? }),

            #[cfg(target_arch = "x86")]
            Key::SYSINFO => Entry::SysInfo(val),

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Key::SYSINFO_EHDR => Entry::SysInfoEHdr(val),

            _ => {
                return {
                    self.index += 2;
                    self.next()
                }
            }
        };

        self.index += 2;
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
            let mut val = core::mem::MaybeUninit::<T>::uninit();
            let size = core::mem::size_of::<T>();
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
            let size = core::mem::size_of::<T>() * val.len();
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

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::RANDOM);
        let s: &[u8; 16] = unsafe { core::mem::transmute(value) };
        assert_eq!(s, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::GID);
        assert_eq!(value, 1000);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::UID);
        assert_eq!(value, 1000);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::PLATFORM);
        let cstr = unsafe { CStr::from_ptr(value as *const u8 as _) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, "x86_64");

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::EXECFN);
        let cstr = unsafe { CStr::from_ptr(value as _) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, prog);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::NULL);
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

        let reader = unsafe { Reader::new(handle.start_ptr()) };
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

        let reader = unsafe { Reader::new(handle.start_ptr()) };
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
        extern "C" {
            static environ: *const *const std::os::raw::c_char;
        }

        let reader = unsafe {
            let mut ptr = environ as *const usize;
            ptr = ptr.sub(1);
            assert_eq!(*ptr, 0);
            ptr = ptr.sub(1);

            let mut len = 0;
            while *ptr != len {
                ptr = ptr.sub(1);
                len += 1;
            }

            Reader::new(&*(ptr as *const ()))
        };

        assert_eq!(reader.count(), 1);

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
}
