// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod accept;
mod accept4;
mod alloc;
mod bind;
mod clock_getres;
mod clock_gettime;
mod connect;
mod epoll_ctl;
mod epoll_pwait;
mod epoll_wait;
mod fcntl;
mod getsockname;
mod ioctl;
mod nanosleep;
mod open;
mod passthrough;
mod poll;
mod read;
mod readv;
mod recv;
mod recvfrom;
mod send;
mod sendto;
mod setsockopt;
mod stub;
mod write;
mod writev;

pub mod types;

pub use accept::*;
pub use accept4::*;
pub use alloc::*;
pub use bind::*;
pub(crate) use clock_getres::*;
pub(crate) use clock_gettime::*;
pub use connect::*;
pub use epoll_ctl::*;
pub use epoll_pwait::EpollPwait;
pub use epoll_wait::*;
pub use fcntl::Fcntl;
pub use getsockname::*;
pub use ioctl::*;
pub use nanosleep::*;
pub use open::*;
pub use passthrough::*;
pub use poll::*;
pub use read::*;
pub use readv::Readv;
pub use recv::*;
pub use recvfrom::*;
pub use send::*;
pub use sendto::*;
pub use setsockopt::*;
pub use stub::*;
pub use write::*;
pub use writev::Writev;

/// Computes the sum of length of all `iovec` elements in a `iov`.
pub(super) fn iov_len<'a, T, U>(iter: &'a T) -> usize
where
    T: ?Sized,
    &'a T: IntoIterator<Item = U>,
    U: AsRef<[u8]>,
{
    iter.into_iter().map(|iov| iov.as_ref().len()).sum()
}
