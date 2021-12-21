// SPDX-License-Identifier: Apache-2.0

//! Shared `sallyport` item definitions.

use crate::iter::Iterator;
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
}

impl TryFrom<usize> for Kind {
    type Error = Error;

    #[inline]
    fn try_from(kind: usize) -> Result<Self, Self::Error> {
        match kind {
            kind if kind == Kind::End as _ => Ok(Kind::End),
            kind if kind == Kind::Syscall as _ => Ok(Kind::Syscall),
            _ => Err(EINVAL),
        }
    }
}

/// `sallyport` item header.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Header {
    pub size: usize,
    pub kind: Kind,
}

impl TryFrom<[usize; 2]> for Header {
    type Error = Error;

    #[inline]
    fn try_from(header: [usize; 2]) -> Result<Self, Self::Error> {
        let [size, kind] = header;
        let kind = kind.try_into()?;
        Ok(Self { size, kind })
    }
}

/// Payload of an [Item] of [Kind::Syscall].
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Syscall {
    pub num: usize,
    pub argv: [usize; 6],
    pub ret: [usize; 2],
}

const SYSCALL_USIZE_COUNT: usize = size_of::<Syscall>() / size_of::<usize>();

impl From<&mut [usize; SYSCALL_USIZE_COUNT]> for &mut Syscall {
    #[inline]
    fn from(buf: &mut [usize; SYSCALL_USIZE_COUNT]) -> Self {
        debug_assert_eq!(
            size_of::<Syscall>(),
            SYSCALL_USIZE_COUNT * size_of::<usize>()
        );
        unsafe { &mut *(buf as *mut _ as *mut _) }
    }
}

/// `sallyport` item.
#[derive(Debug, PartialEq)]
pub enum Item<'a> {
    Syscall(&'a mut Syscall, &'a mut [u8]),
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
                if *size % align_of::<usize>() != 0 {
                    debug_assert_eq!(*size % align_of::<usize>(), 0);
                    return None;
                }
                let (payload, tail) = tail.split_at_mut(*size / size_of::<usize>());
                match (*kind).try_into() {
                    Ok(Kind::End) => {
                        debug_assert_eq!(*size, 0);
                        None
                    }
                    Ok(Kind::Syscall) => {
                        debug_assert!(*size >= size_of::<Syscall>());
                        let data_size = size.checked_sub(size_of::<Syscall>())?;

                        debug_assert_eq!(
                            size_of::<Syscall>(),
                            SYSCALL_USIZE_COUNT * size_of::<usize>()
                        );
                        let (syscall, data) = payload.split_at_mut(SYSCALL_USIZE_COUNT);

                        let syscall: &mut [usize; SYSCALL_USIZE_COUNT] = syscall.try_into().ok()?;
                        let (prefix, data, suffix) = unsafe { data.align_to_mut::<u8>() };
                        if !prefix.is_empty() || !suffix.is_empty() || data.len() != data_size {
                            debug_assert!(prefix.is_empty());
                            debug_assert!(suffix.is_empty());
                            debug_assert_eq!(data.len(), data_size);
                            return None;
                        }
                        Some((Some(Item::Syscall(syscall.into(), data)), tail.into()))
                    }
                    Err(_) => Some((None, tail.into())),
                }
            }
            _ => None,
        }
    }
}

impl<'a> Iterator for Block<'a> {
    type Item = Option<Item<'a>>;

    #[inline]
    fn next(self) -> Option<(Self::Item, Block<'a>)> {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_size() {
        assert_eq!(
            size_of::<Syscall>(),
            SYSCALL_USIZE_COUNT * size_of::<usize>()
        )
    }

    #[test]
    fn block() {
        let mut block: [usize; 25] = [
            (SYSCALL_USIZE_COUNT + 1) * size_of::<usize>(), // size
            Kind::Syscall as _,                             // kind
            libc::SYS_read as _,                            // num
            1,                                              // fd
            0,                                              // buf
            4,                                              // count
            0,                                              // -
            0,                                              // -
            0,                                              // -
            -libc::ENOSYS as _,                             // ret
            0,                                              // -
            0xdeadbeef,                                     // data
            /* --------------------- */
            SYSCALL_USIZE_COUNT * size_of::<usize>(), // size
            Kind::Syscall as _,                       // kind
            libc::SYS_exit as _,                      // num
            5,                                        // status
            0,                                        // -
            0,                                        // -
            0,                                        // -
            0,                                        // -
            0,                                        // -
            -libc::ENOSYS as _,                       // ret
            0,                                        // -
            /* --------------------- */
            0,              // size
            Kind::End as _, // kind
        ];

        let (item, tail) = Block::from(&mut block[..]).next().unwrap();
        assert!(
            matches!(item, Some(Item::Syscall (Syscall{ num, argv, ret }, data)) if {
                assert_eq!(*num, libc::SYS_read as _);
                assert_eq!(*argv, [1, 0, 4, 0, 0, 0]);
                assert_eq!(*ret, [-libc::ENOSYS as _, 0]);
                assert_eq!(data, [0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0]);
                true
            })
        );

        let (item, tail) = tail.next().unwrap();
        assert!(
            matches!(item, Some(Item::Syscall (Syscall{ num, argv, ret }, data)) if {
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
