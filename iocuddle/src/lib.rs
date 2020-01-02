// Copyright 2019 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `iocuddle` is a library for building runtime-safe `ioctl()` interfaces.
//!
//! Existing approaches to interfacing with `ioctl`s from Rust rely on casting
//! and/or unsafe code declarations at the call site. This moves the burden of
//! safety to the consumer of the `ioctl` interface, which is less than ideal.
//!
//! In contrast, `iocuddle` attempts to move the unsafe code burden to `ioctl`
//! definition. Once an `ioctl` is defined, all executions of that `ioctl` can
//! be done within safe code.
//!
//! # Interfaces
//!
//! `iocuddle` aims to handle >=99% of the kernel's `ioctl` interfaces.
//! However, we do not aim to handle all possible `ioctl` interfaces. We will
//! outline the different `ioctl` interfaces below.
//!
//! ## Classic Interfaces
//!
//! Classic `ioctl` interfaces are those `ioctl`s which were created before
//! the modern interfaces we will see below. They basically allowed the full
//! usage of the `ioctl` libc function which is defined as this:
//!
//! ```
//! use std::os::raw::{c_int, c_ulong};
//! extern "C" { fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int; }
//! ```
//!
//! This interface can take any number of any type of arguments and can return
//! any positive integer (with `-1` reserved for indicating an error in
//! combination with `errno`).
//!
//! One major drawback of this interface is that it entirely punts on compiler
//! checking of type safety. A particular `request` is implicitly associated
//! with one or more types that are usually listed in the relevant `ioctl` man
//! page. If the programmer gets any of the types wrong, you end up with
//! corrupted memory.
//!
//! The problems with this interface were recognized early on. Therefore,
//! most `ioctl`s support only a single argument to reduce complexity. But
//! this does not solve the problem of the lack of compiler-enforced type
//! safety.
//!
//! `iocuddle` does not currently support `ioctl`s with multiple arguments.
//! Otherwise, classic `ioctl` interfaces can be defined and used via the
//! `Ioctl::classic()` constructor as follows:
//!
//! ```
//! use std::os::raw::{c_void, c_int, c_uint};
//! use iocuddle::*;
//!
//! let mut file = std::fs::File::open("/dev/tty").unwrap();
//!
//! // This is the simplist ioctl call. The request number is provided via the
//! // Ioctl::classic() constructor. This ioctl reads a C integer from the
//! // kernel by internally passing a reference to a c_int as the argument to
//! // the ioctl. This c_int is returned in the Ok status of the ioctl Result.
//! //
//! // Notice that since the state of the file descriptor is not modified via
//! // this ioctl, we define it using the Read parameter.
//! const TIOCINQ: Ioctl<Read, &c_int> = unsafe { Ioctl::classic(0x541B) };
//! assert_eq!(TIOCINQ.ioctl(&file).unwrap(), (0 as c_uint, 0 as c_int));
//!
//! // This ioctl is similar to the previous one. It differs in two important
//! // respects. First, this raw ioctl takes an input argument rather than an
//! // output argument. This raw argument is a C integer *NOT* a reference to
//! // a C integer. Second, since this ioctl modifies the state of the file
//! // descriptor we use Write instead of Read.
//! //
//! // Notice that the return value of the TCSBRK.ioctl() call is the positive
//! // integer returned from the raw ioctl(), unlike the previous example. It
//! // is not the input argument type.
//! const TCSBRK: Ioctl<Write, c_int> = unsafe { Ioctl::classic(0x5409) };
//! assert_eq!(TCSBRK.ioctl(&mut file, 0).unwrap(), 0 as c_uint);
//!
//! // `iocuddle` can also support classic ioctls with no argument. These
//! // always modify the file descriptor state, so the Write parameter is
//! // used.
//! const TIOCSBRK: Ioctl<Write, c_void> = unsafe { Ioctl::classic(0x5427) };
//! const TIOCCBRK: Ioctl<Write, c_void> = unsafe { Ioctl::classic(0x5428) };
//! assert_eq!(TIOCSBRK.ioctl(&mut file).unwrap(), 0);
//! assert_eq!(TIOCCBRK.ioctl(&mut file).unwrap(), 0);
//! ```
//!
//! ## Modern Interfaces
//!
//! In order to alleviate the type-safety problem with the classic interfaces,
//! the Linux kernel developed a new set of conventions for developing
//! `ioctl`s. We call these conventions the modern interface.
//!
//! Modern `ioctl` interfaces always take a single reference to a struct or
//! integer and return `-1` on failure and `0` (or occasionally another
//! positive integer) on success. The `ioctl` request number is constructed
//! from four parameters:
//!   * a `group` (confusingly called `type` in the kernel macros)
//!   * a `nr` (number)
//!   * a `direction`
//!   * (the size of) a `type`
//!
//! The `group` parameter is used as a namespace to group related `ioctl`s.
//! It is an integer value.
//!
//! The `nr` parameter is an integer discriminator to uniquely identify the
//! `ioctl` within the `group`.
//!
//! The `direction` parameter identifies which direction the data flows. If the
//! data flows from userspace to the kernel, this is the `write` `direction`.
//! If data flows from the kernel to userspace, this is the `read` `direction`.
//! Data which flows both ways is tagged with the `write/read` `direction`.
//!
//! The `type` parameter identifies the type that should be used with this
//! `ioctl`. In the kernel C code this type is only directly used to perturb
//! the `ioctl` request number with the size of the type. `iocuddle`
//! additionally uses this parameter to provide type safety.
//!
//! Defining modern `ioctl`s using `iocuddle` looks like this:
//!
//! ```
//! use iocuddle::*;
//!
//! // Define the Group of KVM ioctls.
//! const KVM: Group = Group::new(0xAE);
//!
//! // Define ioctls within the KVM group.
//! //
//! // The nr is passed to the direction-specific constructor.
//! const KVM_PPC_ALLOCATE_HTAB: Ioctl<WriteRead, &u32> = unsafe { KVM.write_read(0xa7) };
//! const KVM_X86_GET_MCE_CAP_SUPPORTED: Ioctl<Read, &u64> = unsafe { KVM.read(0x9d) };
//! const KVM_X86_SETUP_MCE: Ioctl<Write, &u64> = unsafe { KVM.write(0x9c) };
//! ```
//!
//! # Kernel Documentation
//!
//! For the kernel documentation of the ioctl process, see the following file
//! in the kernel source tree: `Documentation/userspace-api/ioctl/ioctl-number.rst`

#![deny(missing_docs)]
#![deny(clippy::all)]

use core::convert::TryInto;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::null;

use std::io::{Error, Result};
use std::os::raw::{c_int, c_uint, c_ulong, c_void};
use std::os::unix::io::AsRawFd;

extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

/// A marker for the read direction
pub struct Read(());

/// A marker for the write direction
pub struct Write(());

/// A marker for the write/read direction
pub struct WriteRead(());

/// A collection of related `ioctl`s
///
/// In the Linux kernel macros, this is called the `ioctl` `type`. We have
/// chosen a distinct name to disambiguate from the `ioctl` argument type.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Group(u8);

impl Group {
    /// Create a new group for related `ioctl`s from its allocated number
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    // This function implements the _IOC() macro found in the kernel tree at:
    // `include/uapi/asm-generic/ioctl.h`.
    const unsafe fn make<'a, D, T>(self, nr: u8, dir: c_ulong) -> Ioctl<D, &'a T> {
        const SIZE_BITS: c_ulong = 14;
        const SIZE_MASK: c_ulong = (1 << SIZE_BITS) - 1;

        let mut req = dir;

        req <<= SIZE_BITS;
        req |= size_of::<T>() as c_ulong & SIZE_MASK;

        req <<= size_of::<Self>() * 8;
        req |= self.0 as c_ulong;

        req <<= size_of::<u8>() * 8;
        req |= nr as c_ulong;

        Ioctl::classic(req)
    }

    /// Define a new `Read` `ioctl` with an associated `type`
    ///
    /// The `nr` argument is the allocated integer which uniquely
    /// identifies this `ioctl` within the `Group`.
    ///
    /// # Safety
    ///
    /// For safety details, see [Ioctl::classic].
    pub const unsafe fn read<'a, T>(self, nr: u8) -> Ioctl<Read, &'a T> {
        self.make(nr, 0b10)
    }

    /// Define a new `Write` `ioctl` with an associated `type`
    ///
    /// The `nr` argument is the allocated integer which uniquely
    /// identifies this `ioctl` within the `Group`.
    ///
    /// # Safety
    ///
    /// For safety details, see [Ioctl::classic].
    pub const unsafe fn write<'a, T>(self, nr: u8) -> Ioctl<Write, &'a T> {
        self.make(nr, 0b01)
    }

    /// Define a new `WriteRead` `ioctl` with an associated `type`
    ///
    /// The `nr` argument is the allocated integer which uniquely
    /// identifies this `ioctl` within the `Group`.
    ///
    /// # Safety
    ///
    /// For safety details, see [Ioctl::classic].
    pub const unsafe fn write_read<'a, T>(self, nr: u8) -> Ioctl<WriteRead, &'a T> {
        self.make(nr, 0b11)
    }
}

/// A defined `ioctl` along with its associated `direction` and `type`
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ioctl<D, T>(c_ulong, PhantomData<(D, T)>);

impl<D, T> Ioctl<D, T> {
    /// Define a new `ioctl` with an associated `direction` and `type`
    ///
    /// The `request` argument is the allocated integer which uniquely
    /// identifies this `ioctl`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because defining an `ioctl` with an incorrect
    /// `request`, `direction` or argument `type` can later result in memory
    /// corruption. You are responsible to ensure these values are correct.
    ///
    /// Further, you are responsible to ensure that the argument `type` itself
    /// provides appropriate safe wrappers around its raw contents. For some
    /// `type`s none are required. For others, particularly `type`s that pass
    /// pointers to the kernel as `u64`, you need to ensure that things like
    /// lifetimes are correct.
    pub const unsafe fn classic(request: c_ulong) -> Self {
        Self(request, PhantomData)
    }
}

impl Ioctl<Read, c_void> {
    /// Issue an `ioctl` to read a file descriptor's metadata as `c_uint`.
    ///
    /// No argument is supplied to the internal `ioctl()` call. The raw
    /// (positive) return value from the internal `ioctl()` call is returned
    /// on success.
    pub fn ioctl(self, fd: &impl AsRawFd) -> Result<c_uint> {
        let r = unsafe { ioctl(fd.as_raw_fd(), self.0, null::<c_void>()) };

        r.try_into().map_err(|_| Error::last_os_error())
    }
}

impl<T> Ioctl<Read, &T> {
    /// Issue an `ioctl` to read a file descriptor's metadata as type `T`.
    ///
    /// A zeroed instance of type `T` is passed as the first argument to the
    /// internal `ioctl()` call. Upon success, returns the raw (positive)
    /// return value and the instance of `T`.
    pub fn ioctl(self, fd: &impl AsRawFd) -> Result<(c_uint, T)> {
        let mut out: T = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

        let r = unsafe { ioctl(fd.as_raw_fd(), self.0, &mut out as *mut _, null::<c_void>()) };

        r.try_into()
            .map_err(|_| Error::last_os_error())
            .and_then(|x| Ok((x, out)))
    }
}

impl Ioctl<Write, c_void> {
    /// Issue an `ioctl` to modify a file descriptor
    ///
    /// No argument is provided.
    ///
    /// On success, returns the (positive) return value.
    pub fn ioctl(self, fd: &mut impl AsRawFd) -> Result<c_uint> {
        let r = unsafe { ioctl(fd.as_raw_fd(), self.0, null::<c_void>()) };

        r.try_into().map_err(|_| Error::last_os_error())
    }
}

impl Ioctl<Write, c_int> {
    /// Issue an `ioctl` to modify a file descriptor
    ///
    /// A C-integer argument is provided.
    ///
    /// On success, returns the (positive) return value.
    pub fn ioctl(self, fd: &mut impl AsRawFd, data: c_int) -> Result<c_uint> {
        let r = unsafe { ioctl(fd.as_raw_fd(), self.0, data, null::<c_void>()) };

        r.try_into().map_err(|_| Error::last_os_error())
    }
}

impl<T> Ioctl<Write, &T> {
    /// Issue an `ioctl` to modify a file descriptor
    ///
    /// A reference to an immutable instance of `T` is provided as the argument.
    ///
    /// On success, returns the (positive) return value.
    pub fn ioctl(self, fd: &mut impl AsRawFd, data: &T) -> Result<c_uint> {
        let r = unsafe { ioctl(fd.as_raw_fd(), self.0, data as *const _, null::<c_void>()) };

        r.try_into().map_err(|_| Error::last_os_error())
    }
}

impl<T> Ioctl<WriteRead, &T> {
    /// Issue an `ioctl` to modify a file descriptor and read its metadata
    ///
    /// A reference to a mutable instance of `T` is provided as the argument.
    ///
    /// On success, returns the (positive) return value.
    pub fn ioctl(self, fd: &mut impl AsRawFd, data: &mut T) -> Result<c_uint> {
        let r = unsafe { ioctl(fd.as_raw_fd(), self.0, data as *mut _, null::<c_void>()) };

        r.try_into().map_err(|_| Error::last_os_error())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const KVMIO: Group = Group::new(0xAE);

    #[test]
    fn req_r() {
        const KVM_X86_GET_MCE_CAP_SUPPORTED: Ioctl<Read, &u64> = unsafe { KVMIO.read(0x9d) };

        assert_eq!(KVM_X86_GET_MCE_CAP_SUPPORTED.0, 0x8008_ae9d);
    }

    #[test]
    fn req_w() {
        const KVM_X86_SETUP_MCE: Ioctl<Write, &u64> = unsafe { KVMIO.write(0x9c) };

        assert_eq!(KVM_X86_SETUP_MCE.0, 0x4008_ae9c);
    }

    #[test]
    fn req_wr() {
        const KVM_PPC_ALLOCATE_HTAB: Ioctl<WriteRead, &u32> = unsafe { KVMIO.write_read(0xa7) };

        assert_eq!(KVM_PPC_ALLOCATE_HTAB.0, 0xc004_aea7);
    }
}
