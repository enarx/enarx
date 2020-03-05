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
                (Key::Platform, self.push_data(x.as_bytes())? as _)
            }
            Entry::BasePlatform(x) => {
                self.push_data(0u8)?;
                (Key::BasePlatform, self.push_data(x.as_bytes())? as _)
            }
            Entry::ExecFilename(x) => {
                self.push_data(0u8)?;
                (Key::ExecFilename, self.push_data(x.as_bytes())? as _)
            }
            Entry::Random(x) => (Key::Random, self.push_data(&x[..])? as _),
            Entry::ExecFd(v) => (Key::ExecFd, v),
            Entry::PHdr(v) => (Key::PHdr, v),
            Entry::PHent(v) => (Key::PHent, v),
            Entry::PHnum(v) => (Key::PHnum, v),
            Entry::PageSize(v) => (Key::Pagesize, v),
            Entry::Base(v) => (Key::Base, v),
            Entry::Flags(v) => (Key::Flags, v),
            Entry::Entry(v) => (Key::Entry, v),
            Entry::NotElf(v) => (Key::NotElf, if v { 1 } else { 0 }),
            Entry::Uid(v) => (Key::Uid, v),
            Entry::EUid(v) => (Key::EUid, v),
            Entry::Gid(v) => (Key::Gid, v),
            Entry::EGid(v) => (Key::EGid, v),
            Entry::HWCap(v) => (Key::HWCap, v),
            Entry::ClockTick(v) => (Key::ClockTick, v),
            Entry::Secure(v) => (Key::Secure, if v { 1 } else { 0 }),
            Entry::HWCap2(v) => (Key::HWCap2, v),
        };
        self.push_item(key as usize)?;
        self.push_item(value)?;
        Ok(())
    }

    /// Finish the Builder and get the `Handle`
    #[inline]
    pub fn done(mut self) -> Result<Handle<'a>> {
        self.push_item(Key::default() as usize)?;
        self.push_item(usize::default())?;

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
        assert_eq!(key, Key::Random);
        let s: &[u8; 16] = unsafe { core::mem::transmute(value) };
        assert_eq!(s, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::Gid);
        assert_eq!(value, 1000);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::Uid);
        assert_eq!(value, 1000);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::Platform);
        let cstr = unsafe { CStr::from_ptr(value as *const u8 as _) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, "x86_64");

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::ExecFilename);
        let cstr = unsafe { CStr::from_ptr(value as _) };
        let s = cstr.to_string_lossy();
        assert_eq!(s, prog);

        let key: Key = prep_stack.pop_l();
        let value: usize = prep_stack.pop_l();
        assert_eq!(key, Key::Null);
        assert_eq!(value, 0);
    }
}
