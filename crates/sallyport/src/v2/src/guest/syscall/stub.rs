// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::{Allocator, Collect, Collector, CommitPassthrough};
use crate::guest::Call;
use crate::Result;

use libc::{gid_t, pid_t, uid_t};

// TODO: Introduce a macro for trait implementations.
// https://github.com/enarx/sallyport/issues/53

/// Fake GID returned by enarx.
pub const FAKE_GID: gid_t = 1000;

/// Fake PID returned by enarx.
pub const FAKE_PID: pid_t = 1000;

/// Fake UID returned by enarx.
pub const FAKE_UID: uid_t = 1000;

pub struct Getegid;

impl Call<'_> for Getegid {
    type Staged = Self;
    type Committed = Self;
    type Collected = gid_t;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Getegid {}
impl Collect for Getegid {
    type Item = gid_t;

    fn collect(self, _: &impl Collector) -> Self::Item {
        FAKE_GID
    }
}

pub struct Geteuid;

impl Call<'_> for Geteuid {
    type Staged = Self;
    type Committed = Self;
    type Collected = uid_t;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Geteuid {}
impl Collect for Geteuid {
    type Item = uid_t;

    fn collect(self, _: &impl Collector) -> Self::Item {
        FAKE_UID
    }
}

pub struct Getgid;

impl Call<'_> for Getgid {
    type Staged = Self;
    type Committed = Self;
    type Collected = gid_t;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Getgid {}
impl Collect for Getgid {
    type Item = gid_t;

    fn collect(self, _: &impl Collector) -> Self::Item {
        FAKE_GID
    }
}

pub struct Getpid;

impl Call<'_> for Getpid {
    type Staged = Self;
    type Committed = Self;
    type Collected = pid_t;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Getpid {}
impl Collect for Getpid {
    type Item = pid_t;

    fn collect(self, _: &impl Collector) -> Self::Item {
        FAKE_PID
    }
}

pub struct Getuid;

impl Call<'_> for Getuid {
    type Staged = Self;
    type Committed = Self;
    type Collected = uid_t;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Getuid {}
impl Collect for Getuid {
    type Item = uid_t;

    fn collect(self, _: &impl Collector) -> Self::Item {
        FAKE_UID
    }
}
