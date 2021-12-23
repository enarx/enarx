// SPDX-License-Identifier: Apache-2.0

use super::alloc::{phase, Alloc, Allocator, Collect, Commit, Committer, Stage};
use super::{syscall, Platform};
use crate::{item, Result};

use libc::{c_int, size_t, ENOSYS};

pub trait Execute {
    type Platform: Platform;
    type Allocator: Allocator;

    fn platform(&mut self) -> &mut Self::Platform;

    fn allocator(&mut self) -> Self::Allocator;

    /// Executes an arbitrary call.
    /// Examples of calls that this method can execute are:
    /// - [`syscall::Read`]
    /// - [`syscall::Exit`]
    fn execute<'a, T>(
        &mut self,
        req: impl Stage<'a, Item = impl Commit<Item = impl Collect<Item = T>>>,
    ) -> Result<T> {
        let mut alloc = self.allocator();
        let ((staged, len), mut end_ref) =
            alloc.reserve_input(|alloc| alloc.section(|alloc| req.stage(alloc)))?;

        let alloc = alloc.commit();
        let committed = staged.commit(&alloc);
        if len > 0 {
            end_ref.copy_from(
                &alloc,
                item::Header {
                    kind: item::Kind::End,
                    size: 0,
                },
            );
            self.platform().sally()?;
        }

        let alloc = alloc.collect();
        Ok(committed.collect(&alloc))
    }

    /// Loops infinitely trying to exit.
    fn attacked(&mut self) -> ! {
        loop {
            let _ = self.exit(1);
        }
    }

    /// Executes a supported syscall expressed as an opaque 7-word array akin to [`libc::syscall`].
    unsafe fn syscall(&mut self, registers: [usize; 7]) -> Result<[usize; 2]> {
        let [num, argv @ ..] = registers;
        match (num as _, argv) {
            (libc::SYS_read, [fd, buf, count, ..]) => {
                let buf = self.platform().validate_slice_mut(buf, count)?;
                self.read(fd as _, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_exit, [status, ..]) => self.exit(status as _).map(|_| self.attacked()),
            _ => Err(ENOSYS),
        }
    }

    /// Executes [`read`](https://man7.org/linux/man-pages/man2/read.2.html) syscall akin to [`libc::read`].
    fn read(&mut self, fd: c_int, buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Read { fd, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`exit`](https://man7.org/linux/man-pages/man2/exit.2.html) syscall akin to [`libc::exit`].
    fn exit(&mut self, status: c_int) -> Result<()> {
        self.execute(syscall::Exit { status })?;
        self.attacked()
    }
}

/// Guest request handler.
pub struct Handler<'a, P: Platform> {
    alloc: Alloc<'a, phase::Init>,
    platform: P,
}

impl<'a, P: Platform> Handler<'a, P> {
    /// Creates a new [`Handler`] given a mutable borrow of the sallyport block and a [`Platform`].
    pub fn new(block: &'a mut [usize], platform: P) -> Self {
        Self {
            alloc: Alloc::new(block),
            platform,
        }
    }
}

impl<'a, P: Platform> Execute for Handler<'a, P> {
    type Platform = P;
    type Allocator = Alloc<'a, phase::Stage>;

    fn platform(&mut self) -> &mut Self::Platform {
        &mut self.platform
    }

    fn allocator(&mut self) -> Self::Allocator {
        self.alloc.stage()
    }
}
