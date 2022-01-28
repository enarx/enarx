// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::{Allocator, Collect, Collector, CommitPassthrough};
use crate::guest::Call;
use crate::Result;

use libc::{c_char, c_int, c_uint, gid_t, pid_t, sigset_t, size_t, stack_t, uid_t, utsname};

// TODO: Introduce a macro for trait implementations.
// https://github.com/enarx/sallyport/issues/53

/// Fake GID returned by enarx.
pub const FAKE_GID: gid_t = 1000;

/// Fake PID returned by enarx.
pub const FAKE_PID: pid_t = 1000;

/// Fake TID returned by enarx.
pub const FAKE_TID: pid_t = 1;

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

pub struct Getrandom<'a> {
    pub buf: &'a mut [u8],
    pub flags: c_uint,
}

impl Call<'_> for Getrandom<'_> {
    type Staged = Self;
    type Committed = Self;
    type Collected = Result<size_t>;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Getrandom<'_> {}
impl Collect for Getrandom<'_> {
    type Item = Result<size_t>;

    fn collect(self, _: &impl Collector) -> Self::Item {
        let flags = self.flags & !(libc::GRND_NONBLOCK | libc::GRND_RANDOM);
        if flags != 0 {
            return Err(libc::EINVAL);
        }

        for (i, chunk) in self.buf.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if (self.flags & libc::GRND_NONBLOCK) != 0 {
                        return Err(libc::EAGAIN);
                    }
                    if (self.flags & libc::GRND_RANDOM) != 0 {
                        return Ok(i.checked_mul(8).unwrap());
                    }
                }
            }
        }
        Ok(self.buf.len())
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

pub struct Readlink<'a> {
    pub pathname: &'a [u8],
    pub buf: &'a mut [u8],
}

impl Call<'_> for Readlink<'_> {
    type Staged = Self;
    type Committed = Self;
    type Collected = Option<Result<size_t>>;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Readlink<'_> {}
impl Collect for Readlink<'_> {
    type Item = Option<Result<size_t>>;

    fn collect(self, _: &impl Collector) -> Self::Item {
        if !self.pathname.eq("/proc/self/exe".as_bytes()) {
            return Some(Err(libc::ENOENT));
        }

        const DEST: &[u8; 6] = b"/init\0";
        if self.buf.len() < DEST.len() {
            return Some(Err(libc::EINVAL));
        }
        self.buf[..DEST.len()].copy_from_slice(DEST);
        Some(Ok(DEST.len()))
    }
}

pub struct RtSigprocmask<'a> {
    pub how: c_int,
    pub set: Option<&'a sigset_t>,
    pub oldset: Option<&'a mut sigset_t>,
    pub sigsetsize: size_t,
}

impl Call<'_> for RtSigprocmask<'_> {
    type Staged = Self;
    type Committed = Self;
    type Collected = Result<()>;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for RtSigprocmask<'_> {}
impl Collect for RtSigprocmask<'_> {
    type Item = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Item {
        Ok(())
    }
}

pub struct Sigaltstack<'a> {
    pub ss: &'a stack_t,
    pub old_ss: Option<&'a mut stack_t>,
}

impl Call<'_> for Sigaltstack<'_> {
    type Staged = Self;
    type Committed = Self;
    type Collected = Result<()>;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Sigaltstack<'_> {}
impl Collect for Sigaltstack<'_> {
    type Item = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Item {
        Ok(())
    }
}

pub struct SetTidAddress<'a> {
    pub tidptr: &'a mut c_int,
}

impl Call<'_> for SetTidAddress<'_> {
    type Staged = Self;
    type Committed = Self;
    type Collected = pid_t;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for SetTidAddress<'_> {}
impl Collect for SetTidAddress<'_> {
    type Item = pid_t;

    fn collect(self, _: &impl Collector) -> Self::Item {
        FAKE_TID
    }
}

pub struct Uname<'a> {
    pub buf: &'a mut utsname,
}

impl Call<'_> for Uname<'_> {
    type Staged = Self;
    type Committed = Self;
    type Collected = Result<()>;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl CommitPassthrough for Uname<'_> {}
impl Collect for Uname<'_> {
    type Item = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Item {
        fn fill(buf: &mut [c_char; 65], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0) as _;
            }
        }
        fill(&mut self.buf.sysname, "Linux");
        fill(&mut self.buf.nodename, "localhost.localdomain");
        fill(&mut self.buf.release, "5.6.0");
        fill(&mut self.buf.version, "#1");
        fill(&mut self.buf.machine, "x86_64");
        Ok(())
    }
}
