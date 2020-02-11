// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

use std::io::Result;
use std::marker::PhantomData;
use std::ops::*;
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;

use addr::{Address, Offset};
use bitflags::bitflags;
use span::Span;

pub use libc::off_t;

// rust-libc is not exhaustive on these flags.
// For details on the missing ones:
// https://github.com/enarx/enarx/issues/239
bitflags! {
    pub struct Flags: c_int {
        const ANON = libc::MAP_ANON;
        const ANONYMOUS = libc::MAP_ANONYMOUS;
        const BIT32 = libc::MAP_32BIT;
        const DENYWRITE = libc::MAP_DENYWRITE;
        const EXECUTABLE = libc::MAP_EXECUTABLE;
        const FIXED = libc::MAP_FIXED;
        const FIXED_NOREPLACE = Flags::SYNC.bits << 1;
        const GROWSDOWN = libc::MAP_GROWSDOWN;
        const HUGETLB = libc::MAP_HUGETLB;
        const LOCKED = libc::MAP_LOCKED;
        const NONBLOCK = libc::MAP_NONBLOCK;
        const NORESERVE = libc::MAP_NORESERVE;
        const POPULATE = libc::MAP_POPULATE;
        const PRIVATE = libc::MAP_PRIVATE;
        const SHARED = libc::MAP_SHARED;
        const SHARED_VALIDATE = libc::MAP_SHARED | libc::MAP_PRIVATE;
        const STACK = libc::MAP_STACK;
        const SYNC = Flags::HUGETLB.bits << 1;
    }
}

bitflags! {
    pub struct Protections: c_int {
        const EXEC = libc::PROT_EXEC;
        const READ = libc::PROT_READ;
        const WRITE = libc::PROT_WRITE;
    }
}

#[derive(Clone)]
struct Info {
    span: Span<Address<usize>, Offset<usize>>,
    protections: Protections,
    flags: Flags,
}

pub struct Builder<'a, T> {
    info: Info,
    fd: c_int,
    offset: off_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> Builder<'a, T> {
    /// Sets the protections for the mapping
    pub fn protections(mut self, protections: Protections) -> Self {
        self.info.protections = protections;
        self
    }

    /// Sets the flags for the mapping
    pub fn flags(mut self, flags: Flags) -> Self {
        self.info.flags = flags;
        self
    }

    /// Sets the file descriptor and offset for the mapping
    pub fn file(mut self, file: &'a mut impl AsRawFd, offset: off_t) -> Self {
        self.fd = file.as_raw_fd();
        self.offset = offset;
        self
    }

    /// # Safety
    ///
    /// This function calls the underlying `mmap()`, which is inherently unsafe.
    unsafe fn mmap(mut self) -> Result<Info> {
        let addr = libc::mmap(
            self.info.span.start.inner() as _,
            self.info.span.count.inner(),
            self.info.protections.bits,
            self.info.flags.bits,
            self.fd,
            self.offset,
        );

        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        self.info.span.start = Address::new(addr as _);
        Ok(self.info)
    }
}

impl<'a> Builder<'a, Mapping> {
    /// Creates a new mapping builder
    ///
    /// Requires the length of the mapping.
    pub fn new(length: Offset<usize>) -> Self {
        Self {
            info: Info {
                span: Span {
                    start: 0.into(),
                    count: length,
                },
                protections: Protections::empty(),
                flags: Flags::PRIVATE | Flags::ANONYMOUS,
            },
            fd: -1,
            offset: 0,
            phantom: PhantomData,
        }
    }

    /// Sets the address for the mapping
    pub fn address(mut self, addr: Address<usize>) -> Self {
        self.info.span.start = addr;
        self
    }

    /// Consumes the builder and creates the mapping
    ///
    /// # Safety
    ///
    /// This function calls the underlying `mmap()`, which is inherently unsafe.
    pub unsafe fn map(self) -> Result<Mapping> {
        Ok(Mapping(self.mmap()?))
    }
}

impl<'a> Builder<'a, ()> {
    /// Consumes the builder and updates the mapping
    ///
    /// # Safety
    ///
    /// This function calls the underlying `mmap()`, which is inherently unsafe.
    pub unsafe fn update(self) -> Result<()> {
        self.mmap()?;
        Ok(())
    }
}

pub struct Mapping(Info);

impl Mapping {
    /// The address of the mapping
    pub fn address(&self) -> Address<usize> {
        self.0.span.start
    }

    /// The length of the mapping
    pub fn length(&self) -> Offset<usize> {
        self.0.span.count
    }

    /// The protections of the mapping
    pub fn protections(&self) -> Protections {
        self.0.protections
    }

    /// The flags of the mapping
    pub fn flags(&self) -> Flags {
        self.0.flags
    }

    /// Remap a section of the mapping
    ///
    /// This function changes properties for all or part of the original
    /// mapping. It DOES NOT take ownership of the new sub-mapping.
    ///
    /// The `offset` is an offset into the original mapping. The `length` is
    /// the length of the subset that you want to remap. The address of the
    /// new mapping is calculated internally. The protections default to the
    /// initial protections for the region, that is the ones set during the
    /// initial mapping. The flags are copied from the initial flags for the
    /// region, with `Flags::FIXED_NOREPLACE` unconditionally removed and
    /// `Flags::FIXED` unconditionally added.
    ///
    /// We do not retain the original file descriptor. So if you need to
    /// specify it again, you must do so yourself.
    pub fn remap<'a>(
        &'a mut self,
        offset: Offset<usize>,
        length: Offset<usize>,
    ) -> Result<Builder<'a, ()>> {
        if offset + length > self.0.span.count {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }

        Ok(Builder {
            info: Info {
                span: Span {
                    start: self.0.span.start + offset,
                    count: length,
                },
                protections: self.0.protections,
                flags: (self.0.flags & !Flags::FIXED_NOREPLACE) | Flags::FIXED,
            },
            fd: -1,
            offset: 0,
            phantom: PhantomData,
        })
    }

    /// Unmaps part of the mapping
    ///
    /// Unmaps `length` bytes from the `front` or back of the existing mapping.
    ///
    /// # Safety
    ///
    /// This function calls the underlying `munmap()`, which is inherently unsafe.
    pub unsafe fn trim(mut self, front: bool, length: Offset<usize>) -> Result<Self> {
        if length >= self.0.span.count {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }

        let (keep, dump) = if front {
            let split = self.0.span.split(length);
            (split.1, split.0)
        } else {
            self.0.span.split(self.0.span.count - length)
        };

        if libc::munmap(dump.start.inner() as _, dump.count.inner()) == -1 {
            return Err(std::io::Error::last_os_error());
        }

        self.0.span = keep;
        Ok(self)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0.span.start.inner() as _, self.0.span.count.inner()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use units::bytes;

    const LENGTH: Offset<usize> = Offset::new(bytes![1; MiB]);

    #[test]
    fn defaults() {
        assert_eq!(
            unsafe { Builder::new(LENGTH).map() }.unwrap().length(),
            LENGTH
        );
    }

    #[test]
    fn r() {
        assert_eq!(
            unsafe { Builder::new(LENGTH).protections(Protections::READ).map() }
                .unwrap()
                .length(),
            LENGTH
        );
    }

    #[test]
    fn w() {
        assert_eq!(
            unsafe { Builder::new(LENGTH).protections(Protections::WRITE).map() }
                .unwrap()
                .length(),
            LENGTH
        );
    }

    #[test]
    fn x() {
        assert_eq!(
            unsafe { Builder::new(LENGTH).protections(Protections::EXEC).map() }
                .unwrap()
                .length(),
            LENGTH
        );
    }

    #[test]
    fn rw() {
        assert_eq!(
            unsafe {
                Builder::new(LENGTH)
                    .protections(Protections::READ | Protections::WRITE)
                    .map()
            }
            .unwrap()
            .length(),
            LENGTH
        );
    }

    #[test]
    fn rx() {
        assert_eq!(
            unsafe {
                Builder::new(LENGTH)
                    .protections(Protections::READ | Protections::EXEC)
                    .map()
            }
            .unwrap()
            .length(),
            LENGTH
        );
    }

    #[test]
    fn wx() {
        assert_eq!(
            unsafe {
                Builder::new(LENGTH)
                    .protections(Protections::WRITE | Protections::EXEC)
                    .map()
            }
            .unwrap()
            .length(),
            LENGTH
        );
    }

    #[test]
    fn rwx() {
        assert_eq!(
            unsafe {
                Builder::new(LENGTH)
                    .protections(Protections::READ | Protections::WRITE | Protections::EXEC)
                    .map()
            }
            .unwrap()
            .length(),
            LENGTH
        );
    }

    #[test]
    fn shared() {
        let mut file = std::fs::File::open("/dev/zero").unwrap();

        assert_eq!(
            unsafe {
                Builder::new(LENGTH)
                    .flags(Flags::SHARED)
                    .file(&mut file, 0)
                    .map()
            }
            .unwrap()
            .length(),
            LENGTH
        );
    }

    #[test]
    fn fixed_noreplace() {
        let mut file = std::fs::File::open("/dev/zero").unwrap();

        // Try to forcibly allocate at that address.
        assert_eq!(
            unsafe {
                Builder::new(LENGTH)
                    .address(bytes![1; MiB].into())
                    .flags(Flags::SHARED | Flags::FIXED_NOREPLACE)
                    .file(&mut file, 0)
                    .map()
            }
            .unwrap()
            .length(),
            LENGTH
        );
    }
}
