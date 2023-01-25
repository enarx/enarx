// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector};
use crate::item::enarxcall::Number;
use crate::Result;

use core::ffi::{c_int, c_void};
use core::ptr::NonNull;

/// Trait implemented by allocatable Enarx calls, which are passed through directly to the host and do
/// not require custom handling logic.
pub trait PassthroughAlloc {
    /// Enarx call number.
    ///
    /// For example, [`Number::BalloonMemory`].
    const NUM: Number;

    /// The Enarx call argument vector.
    ///
    /// For example, [`call::types::Argv<3>`](crate::guest::call::types::Argv<3>).
    type Argv: Into<[usize; 4]>;

    /// Enarx call return value.
    ///
    /// For example, `usize`.
    type Ret;

    /// Returns argument vector registers.
    fn stage(self) -> Self::Argv;
}

impl<'a, T: PassthroughAlloc> Alloc<'a> for T {
    const NUM: Number = T::NUM;

    type Argv = T::Argv;
    type Ret = T::Ret;

    type Staged = ();
    type Committed = ();
    type Collected = Result<T::Ret>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((T::stage(self), ()))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}

/// Request an additional memory region.
pub struct BalloonMemory {
    /// Page size expressed as an exponent of 2.
    pub size_exponent: usize,
    /// Number of pages to allocate.
    pub pages: usize,
    /// Guest physical address where the memory should be allocated.
    pub addr: *mut c_void,
}

impl PassthroughAlloc for BalloonMemory {
    const NUM: Number = Number::BalloonMemory;

    type Argv = Argv<3>;
    type Ret = usize;

    fn stage(self) -> Self::Argv {
        Argv([self.size_exponent, self.pages, self.addr as _])
    }
}

/// Get the size of the SGX Quote
#[repr(transparent)]
pub struct GetSgxQuoteSize;

impl PassthroughAlloc for GetSgxQuoteSize {
    const NUM: Number = Number::GetSgxQuoteSize;

    type Argv = Argv<0>;
    type Ret = usize;

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}

/// Get number of memory slots available for ballooning from the host.
#[repr(transparent)]
pub struct MemInfo;

impl PassthroughAlloc for MemInfo {
    const NUM: Number = Number::MemInfo;

    type Argv = Argv<0>;
    type Ret = usize;

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}

/// Notify the host to prepare memory for the guest to handle
/// [Mmap](crate::guest::call::syscall::Mmap).
pub struct MmapHost {
    pub addr: NonNull<c_void>,
    pub length: usize,
    pub prot: c_int,
}

impl PassthroughAlloc for MmapHost {
    const NUM: Number = Number::MmapHost;

    type Argv = Argv<3>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.addr.as_ptr() as _, self.length, self.prot as _])
    }
}

/// Notify the host to prepare memory for the guest to handle
/// [Mprotect](crate::guest::call::syscall::Mprotect).
pub struct MprotectHost {
    pub addr: NonNull<c_void>,
    pub length: usize,
    pub prot: c_int,
}

impl PassthroughAlloc for MprotectHost {
    const NUM: Number = Number::MprotectHost;

    type Argv = Argv<3>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.addr.as_ptr() as _, self.length, self.prot as _])
    }
}

/// Notify the host to prepare memory for the guest to handle
/// [Munmap](crate::guest::call::syscall::Munmap).
pub struct MunmapHost {
    pub addr: NonNull<c_void>,
    pub length: usize,
}

impl PassthroughAlloc for MunmapHost {
    const NUM: Number = Number::MunmapHost;

    type Argv = Argv<2>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.addr.as_ptr() as _, self.length])
    }
}

/// Notify the host about a new sallyport block at `addr` given the `index`.
pub struct NewSallyport {
    pub addr: NonNull<c_void>,
    pub index: usize,
}

impl PassthroughAlloc for NewSallyport {
    const NUM: Number = Number::NewSallyport;

    type Argv = Argv<2>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.addr.as_ptr() as _, self.index])
    }
}

/// Spawn a new thread
#[repr(transparent)]
pub struct Spawn {
    /// An address suitable to start a new thread with the keep's technology.
    /// 0 is a valid value, and indicates that the keep should reuse a thread from the pool.
    pub addr: usize,
}

impl PassthroughAlloc for Spawn {
    const NUM: Number = Number::Spawn;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.addr as _])
    }
}

/// Within an address range inside the enclave, ask host to set page type to
/// the specified type. Address and length must be page-aligned. Shim must validate
/// and acknowledge the changes with ENCLU[EACCEPT], in order for them to
/// take effect.
pub struct ModifySgxPageType {
    pub addr: NonNull<c_void>,
    pub length: usize,
    pub page_type: u8,
}

impl PassthroughAlloc for ModifySgxPageType {
    const NUM: Number = Number::SgxModifyPageType;

    type Argv = Argv<3>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.addr.as_ptr() as _, self.length, self.page_type as _])
    }
}

/// Unpark parked threads
#[repr(transparent)]
pub struct UnPark;

impl PassthroughAlloc for UnPark {
    const NUM: Number = Number::UnPark;

    type Argv = Argv<0>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}
