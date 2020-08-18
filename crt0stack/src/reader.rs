// SPDX-License-Identifier: Apache-2.0

use super::*;

use core::marker::PhantomData;
use core::mem::transmute;

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
    pub unsafe fn from_stack(stack: &'a Stack) -> Self {
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

        let entry = match unsafe { transmute(*self.stack) } {
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
#[allow(clippy::integer_arithmetic)]
mod tests {
    use super::*;

    #[test]
    fn normal() {
        let mut stack = [0u8; 512];

        let mut builder = crate::Builder::new(&mut stack);
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

        let reader = unsafe { Reader::from_stack(&*handle) };
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
    fn skip() {
        let mut stack = [0u8; 512];

        let mut builder = crate::Builder::new(&mut stack);
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

        let reader = unsafe { Reader::from_stack(&*handle) };
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
    fn real() {
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
    fn unknown() {
        #[repr(C, align(16))]
        struct Aligned<T>(T);

        let stack = Aligned([
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
        ]);

        let stack = stack.0.as_ptr() as *const Stack;
        let reader = unsafe { Reader::from_stack(&*stack) };
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
}
