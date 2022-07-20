// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::guest::alloc::{Alloc, Allocator, Collect, Commit, Committer};
use crate::guest::call::kind;
use crate::guest::syscall::types::SockaddrOutput;
use crate::guest::Call;
use crate::item;
use crate::item::syscall;
use crate::libc::socklen_t;
use crate::NULL;

use core::mem::{size_of, transmute};
use libc::{SYS_exit, SYS_recvfrom, AF_INET, ENOSYS};

fn assert_call<'a, K: kind::Kind, T: Call<'a, K>, const N: usize>(
    call: T,
    committed: [usize; N],
    collect: [usize; N],
    collected: T::Collected,
) where
    T::Collected: core::fmt::Debug + core::cmp::PartialEq,
{
    let mut buf = [0usize; N];

    let mut alloc = Alloc::new(&mut buf).stage();

    // Alloc stores a `NonNull<[u8]>` view of the underlying `[usize; N]` buffer.
    // Before it starts advancing the pointer to the buffer by handing out allocations,
    // we grab a copy of the original address, extract the raw pointer to the `*mut u8` buffer,
    // and transmute that to a `*mut [usize; N]` so we can test the buffer contents.
    // The reason that we do this dance after the Alloc has been constructed rather than
    // stash a pointer to the original buffer is to keep Miri happy.
    // Specifically, this avoids ever aliasing any `&mut T`, and preserves pointer provenance.
    let buf_ptr: *mut [usize; N] = unsafe { transmute(alloc.ptr.as_mut_ptr()) };

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
            syscall::USIZE_COUNT * size_of::<usize>(),
            item::Kind::Syscall as _,
            SYS_exit as _,
            2,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            -ENOSYS as _,
            0,
        ],
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
        Ok(()),
    )
}

#[test]
fn recv() {
    let sockfd = 42;
    let flags = 0;
    let mut buf = [42, 42];
    let buf_len = buf.len();
    assert_call(
        Recv {
            sockfd,
            buf: &mut buf,
            flags,
        },
        [
            syscall::USIZE_COUNT * size_of::<usize>() + size_of::<usize>(),
            item::Kind::Syscall as _,
            SYS_recvfrom as _,
            sockfd as _,
            0,
            buf_len,
            flags as _,
            NULL,
            NULL,
            -ENOSYS as _,
            0,
            0,
        ],
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0xedfe,
        ],
        Some(Ok(2)),
    );
    assert_eq!(buf, [0xfe, 0xed]);
}

#[test]
fn recvfrom() {
    let sockfd = 42;
    let flags = 0;
    let mut buf = [42, 42];
    let buf_len = buf.len();
    let mut src_addr = [42, 42, 42, 42, 42, 42, 42];
    let mut addrlen = src_addr.len() as _;
    assert_call(
        Recvfrom {
            sockfd,
            buf: &mut buf,
            flags,
            src_addr: SockaddrOutput::new(&mut src_addr, &mut addrlen),
        },
        [
            syscall::USIZE_COUNT * size_of::<usize>() + 2 * size_of::<usize>(),
            item::Kind::Syscall as _,
            SYS_recvfrom as _,
            sockfd as _,
            size_of::<usize>() + size_of::<socklen_t>(),
            buf_len,
            flags as _,
            0,
            size_of::<usize>(),
            -ENOSYS as _,
            0,
            0,
            7,
        ],
        [
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            2,
            0,
            0x5040302010000 | AF_INET as usize,
            0xedfe00000042,
        ],
        Some(Ok(2)),
    );
    assert_eq!(src_addr, [AF_INET as _, 0, 0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(addrlen, 0x42);
    assert_eq!(buf, [0xfe, 0xed]);
}
