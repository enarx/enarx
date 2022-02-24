// SPDX-License-Identifier: Apache-2.0

use libc::c_void;

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector};
use crate::item::enarxcall::Number;
use crate::Result;

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
