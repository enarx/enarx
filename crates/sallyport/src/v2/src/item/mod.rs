// SPDX-License-Identifier: Apache-2.0

//! Shared `sallyport` item definitions.

pub mod gdbcall;
pub mod syscall;

pub use gdbcall::Payload as Gdbcall;
pub use syscall::Payload as Syscall;

use crate::iter::{IntoIterator, Iterator};
use crate::Error;

use core::convert::{TryFrom, TryInto};
use core::mem::{align_of, size_of};
use libc::EINVAL;

/// `sallyport` item kind.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(usize)]
pub enum Kind {
    End = 0x00,

    Syscall = 0x01,
    Gdbcall = 0x02,
}

impl TryFrom<usize> for Kind {
    type Error = Error;

    #[inline]
    fn try_from(kind: usize) -> Result<Self, Self::Error> {
        match kind {
            kind if kind == Kind::End as _ => Ok(Kind::End),
            kind if kind == Kind::Syscall as _ => Ok(Kind::Syscall),
            kind if kind == Kind::Gdbcall as _ => Ok(Kind::Gdbcall),
            _ => Err(EINVAL),
        }
    }
}

pub(crate) const HEADER_USIZE_COUNT: usize = size_of::<Header>() / size_of::<usize>();

/// `sallyport` item header.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Header {
    pub size: usize,
    pub kind: Kind,
}

impl TryFrom<[usize; HEADER_USIZE_COUNT]> for Header {
    type Error = Error;

    #[inline]
    fn try_from(header: [usize; HEADER_USIZE_COUNT]) -> Result<Self, Self::Error> {
        let [size, kind] = header;
        let kind = kind.try_into()?;
        Ok(Self { size, kind })
    }
}

/// `sallyport` item.
#[derive(Debug, PartialEq)]
pub enum Item<'a> {
    Syscall(&'a mut Syscall, &'a mut [u8]),
    Gdbcall(&'a mut Gdbcall, &'a mut [u8]),
}

/// Untrusted `sallyport` block.
#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct Block<'a>(&'a mut [usize]);

impl<'a> From<&'a mut [usize]> for Block<'a> {
    #[inline]
    fn from(block: &'a mut [usize]) -> Self {
        Self(block)
    }
}

impl<'a> From<Block<'a>> for Option<(Option<Item<'a>>, Block<'a>)> {
    #[inline]
    fn from(block: Block<'a>) -> Self {
        match block.0 {
            [size, kind, tail @ ..] => {
                #[inline]
                fn decode_item<'a, const USIZE_COUNT: usize, T>(
                    size: usize,
                    tail: &'a mut [usize],
                ) -> Option<((&'a mut T, &'a mut [u8]), Block<'a>)>
                where
                    &'a mut T: From<&'a mut [usize; USIZE_COUNT]>,
                {
                    let (payload, tail) = tail.split_at_mut(size / size_of::<usize>());

                    debug_assert!(size >= size_of::<T>());
                    let data_size = size.checked_sub(size_of::<T>())?;

                    debug_assert_eq!(size_of::<T>(), USIZE_COUNT * size_of::<usize>());
                    let (item_payload, data) = payload.split_at_mut(USIZE_COUNT);

                    let item_payload: &mut [usize; USIZE_COUNT] = item_payload.try_into().ok()?;
                    let (prefix, data, suffix) = unsafe { data.align_to_mut::<u8>() };
                    if !prefix.is_empty() || !suffix.is_empty() || data.len() != data_size {
                        debug_assert!(prefix.is_empty());
                        debug_assert!(suffix.is_empty());
                        debug_assert_eq!(data.len(), data_size);
                        return None;
                    }
                    Some(((item_payload.into(), data), tail.into()))
                }

                if *size % align_of::<usize>() != 0 {
                    debug_assert_eq!(*size % align_of::<usize>(), 0);
                    return None;
                }
                match (*kind).try_into() {
                    Ok(Kind::End) => {
                        debug_assert_eq!(*size, 0);
                        None
                    }

                    Ok(Kind::Syscall) => {
                        decode_item::<{ syscall::USIZE_COUNT }, Syscall>(*size, tail)
                            .map(|((call, data), tail)| (Some(Item::Syscall(call, data)), tail))
                    }

                    Ok(Kind::Gdbcall) => {
                        decode_item::<{ gdbcall::USIZE_COUNT }, Gdbcall>(*size, tail)
                            .map(|((call, data), tail)| (Some(Item::Gdbcall(call, data)), tail))
                    }

                    Err(_) => Some((None, tail.split_at_mut(*size / size_of::<usize>()).1.into())),
                }
            }
            _ => None,
        }
    }
}

impl<'a> Iterator for Block<'a> {
    type Item = Item<'a>;

    #[inline]
    fn next(self) -> Option<(Self::Item, Block<'a>)> {
        match self.into() {
            Some((Some(item), tail)) => Some((item, tail)),
            Some((None, tail)) => tail.next(),
            None => None,
        }
    }
}

impl<'a> IntoIterator for Block<'a> {
    type Item = <Self as Iterator>::Item;
    type IntoIter = Self;

    fn into_iter(self) -> Self::IntoIter {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_size() {
        assert_eq!(
            size_of::<Syscall>(),
            syscall::USIZE_COUNT * size_of::<usize>()
        )
    }

    #[test]
    fn block() {
        let mut block: [usize; 3 * HEADER_USIZE_COUNT + 2 * syscall::USIZE_COUNT + 1] = [
            (syscall::USIZE_COUNT + 1) * size_of::<usize>(), // size
            Kind::Syscall as _,                              // kind
            libc::SYS_read as _,                             // num
            1,                                               // fd
            0,                                               // buf
            4,                                               // count
            0,                                               // -
            0,                                               // -
            0,                                               // -
            -libc::ENOSYS as _,                              // ret
            0,                                               // -
            0xdeadbeef,                                      // data
            /* --------------------- */
            syscall::USIZE_COUNT * size_of::<usize>(), // size
            Kind::Syscall as _,                        // kind
            libc::SYS_exit as _,                       // num
            5,                                         // status
            0,                                         // -
            0,                                         // -
            0,                                         // -
            0,                                         // -
            0,                                         // -
            -libc::ENOSYS as _,                        // ret
            0,                                         // -
            /* --------------------- */
            0,              // size
            Kind::End as _, // kind
        ];

        let (item, tail) = Block::from(&mut block[..]).next().unwrap();
        assert!(
            matches!(item, Item::Syscall (Syscall{ num, argv, ret }, data) if {
                assert_eq!(*num, libc::SYS_read as _);
                assert_eq!(*argv, [1, 0, 4, 0, 0, 0]);
                assert_eq!(*ret, [-libc::ENOSYS as _, 0]);
                assert_eq!(data, [0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0]);
                true
            })
        );

        let (item, tail) = tail.next().unwrap();
        assert!(
            matches!(item, Item::Syscall (Syscall{ num, argv, ret }, data) if {
                assert_eq!(*num, libc::SYS_exit as _);
                assert_eq!(*argv, [5, 0, 0, 0, 0, 0]);
                assert_eq!(*ret, [-libc::ENOSYS as _, 0]);
                assert_eq!(data, []);
                true
            })
        );
        assert!(tail.next().is_none());
    }
}
