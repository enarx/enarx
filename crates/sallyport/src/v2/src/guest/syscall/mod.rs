// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod accept;
mod accept4;
mod bind;
mod clock_gettime;
mod connect;
mod epoll_ctl;
mod epoll_pwait;
mod epoll_wait;
mod fcntl;
mod fstat;
mod getsockname;
mod ioctl;
mod passthrough;
mod poll;
mod read;
mod recv;
mod recvfrom;
mod result;
mod send;
mod sendto;
mod setsockopt;
mod stub;
mod write;

pub mod types;

pub use accept::*;
pub use accept4::*;
pub use bind::*;
pub(crate) use clock_gettime::*;
pub use connect::*;
pub use epoll_ctl::*;
pub use epoll_pwait::EpollPwait;
pub use epoll_wait::*;
pub use fcntl::Fcntl;
pub use fstat::*;
pub use getsockname::*;
pub use ioctl::*;
pub use passthrough::*;
pub use poll::*;
pub use read::*;
pub use recv::*;
pub use recvfrom::*;
pub use result::Result;
pub use send::*;
pub use sendto::*;
pub use setsockopt::*;
pub use stub::*;
pub use write::*;
