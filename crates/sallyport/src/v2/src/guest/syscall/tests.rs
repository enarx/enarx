// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::guest::alloc::{Alloc, Allocator, Collect, Commit, Committer, Stage};
use crate::item::{self, SYSCALL_USIZE_COUNT};

use core::marker::PhantomData;
use core::mem::size_of;

pub struct Call<'a, T, U, const N: usize>
where
    T: Stage<'a>,
    T::Item: Commit,
    <T::Item as Commit>::Item: Collect<Item = U>,
{
    pub stage: T,
    pub committed: [usize; N],
    pub collect: [usize; N],
    pub collected: U,

    pub phantom: PhantomData<&'a ()>,
}

impl<'a, T, U, const N: usize> Call<'a, T, U, N>
where
    T: Stage<'a>,
    T::Item: Commit,
    <T::Item as Commit>::Item: Collect<Item = U>,
    U: core::fmt::Debug + core::cmp::PartialEq,
{
    pub fn new(stage: T, committed: [usize; N], collect: [usize; N], collected: U) -> Self {
        Self {
            stage,
            committed,
            collect,
            collected,

            phantom: PhantomData,
        }
    }

    pub fn assert(self) {
        let mut buf = [0usize; N];
        let buf_ptr = &mut buf as *mut [usize; N];

        let mut alloc = Alloc::new(&mut buf).stage();
        let staged = self.stage.stage(&mut alloc).unwrap();

        let alloc = alloc.commit();
        let committed = staged.commit(&alloc);
        assert_eq!(unsafe { buf_ptr.read() }, self.committed,);
        unsafe { buf_ptr.write(self.collect) };

        let alloc = alloc.collect();
        let collected = committed.collect(&alloc);
        assert_eq!(collected, self.collected);
    }
}

#[test]
fn exit() {
    Call::new(
        Exit { status: 2 },
        [
            SYSCALL_USIZE_COUNT * size_of::<usize>(),
            item::Kind::Syscall as _,
            libc::SYS_exit as _,
            2,
            0,
            0,
            0,
            0,
            0,
            -libc::ENOSYS as _,
            0,
        ],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        (),
    )
    .assert()
}
