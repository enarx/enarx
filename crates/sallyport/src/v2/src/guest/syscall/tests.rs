// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::guest::alloc::{Alloc, Allocator, Collect, Commit, Committer};
use crate::guest::Call;
use crate::item::{self, SYSCALL_USIZE_COUNT};

use core::mem::size_of;

fn assert_call<'a, T: Call<'a>, const N: usize>(
    call: T,
    committed: [usize; N],
    collect: [usize; N],
    collected: T::Collected,
) where
    T::Collected: core::fmt::Debug + core::cmp::PartialEq,
{
    let mut buf = [0usize; N];
    let buf_ptr = &mut buf as *mut [usize; N];

    let mut alloc = Alloc::new(&mut buf).stage();
    let call = call.stage(&mut alloc).unwrap();

    let alloc = alloc.commit();
    let call = call.commit(&alloc);
    assert_eq!(unsafe { buf_ptr.read() }, committed);
    unsafe { buf_ptr.write(collect) };

    let alloc = alloc.collect();
    assert_eq!(call.collect(&alloc), collected);
}

#[test]
fn exit() {
    assert_call(
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
        Ok(()),
    )
}
