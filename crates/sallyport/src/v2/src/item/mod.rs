// SPDX-License-Identifier: Apache-2.0

//! Shared `sallyport` item definitions.

use crate::{read_array, Error, SlicePtr};

use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::{slice_from_raw_parts_mut, NonNull};
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

/// `sallyport` item.
#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub enum Item<'a> {
    Syscall {
        ptr: NonNull<(Syscall, [u8])>,
        phantom: PhantomData<&'a ()>,
    },
}

/// Iterator over untrusted `sallyport` block.
#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct Iter<'a>(NonNull<[u8]>, PhantomData<&'a ()>);

impl<'a> Iterator for Iter<'a> {
    type Item = Item<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let capacity = SlicePtr::len(self.0.as_ptr()).checked_sub(2 * size_of::<usize>())?;
        let (header, ptr): (_, *mut u8) = unsafe { read_array(self.0.cast()) };
        let Header { size, kind } = header.try_into().ok()?;
        match kind {
            Kind::End => {
                debug_assert_eq!(size, 0);
                None
            }

            Kind::Syscall => {
                debug_assert_eq!(size % core::mem::align_of::<usize>(), 0);
                let capacity = capacity.checked_sub(size)?;
                self.0 = unsafe {
                    NonNull::new_unchecked(slice_from_raw_parts_mut(ptr.add(size), capacity))
                };
                let data_size = size.checked_sub(size_of::<Syscall>())?;
                Some(Item::Syscall {
                    ptr: unsafe {
                        NonNull::new_unchecked(slice_from_raw_parts_mut(ptr, data_size) as _)
                    },
                    phantom: PhantomData,
                })
            }
        }
    }
}

/// Reference to untrusted `sallyport` block.
#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct Block<'a>(NonNull<[u8]>, PhantomData<&'a ()>);

impl<'a, const N: usize> From<NonNull<[usize; N]>> for Block<'a> {
    #[inline]
    fn from(buffer: NonNull<[usize; N]>) -> Self {
        Self(
            unsafe {
                NonNull::new_unchecked(slice_from_raw_parts_mut(
                    buffer.as_ptr() as _,
                    N * size_of::<usize>(),
                ))
            },
            PhantomData,
        )
    }
}

impl<'a> IntoIterator for Block<'a> {
    type Item = Item<'a>;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter(self.0, PhantomData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_one;

    #[test]
    fn block() {
        let mut block: [usize; 25] = [
            10 * size_of::<usize>(), // size
            Kind::Syscall as _,      // kind
            libc::SYS_read as _,     // num
            1,                       // fd
            0,                       // buf
            2,                       // count
            0,                       // -
            0,                       // -
            0,                       // -
            -libc::ENOSYS as _,      // ret
            0,                       // -
            0xdeadbeef,              // data
            /* --------------------- */
            9 * size_of::<usize>(), // size
            Kind::Syscall as _,     // kind
            libc::SYS_exit as _,    // num
            5,                      // status
            0,                      // -
            0,                      // -
            0,                      // -
            0,                      // -
            0,                      // -
            -libc::ENOSYS as _,     // ret
            0,                      // -
            /* --------------------- */
            0,              // size
            Kind::End as _, // kind
        ];
        let items = Block::from(NonNull::from(&mut block))
            .into_iter()
            .collect::<Vec<Item>>();

        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], Item::Syscall { ptr, .. } if {
            let (Syscall{ num, argv, ret }, data): (_, *mut u32) = unsafe {read_one(ptr.cast())};
            assert_eq!(SlicePtr::len(ptr.as_ptr() as *const [u8]), size_of::<usize>());
            assert_eq!(num, libc::SYS_read as _);
            assert_eq!(argv, [1, 0, 2, 0, 0, 0]);
            assert_eq!(ret, [-libc::ENOSYS as _, 0]);
            assert_eq!(unsafe{ data.read() }, 0xdeadbeef);
            true
        }));
        assert!(matches!(items[1], Item::Syscall { ptr, .. } if {
            let (Syscall{ num, argv, ret }, _): (_, *mut ()) = unsafe {read_one(ptr.cast())};
            assert_eq!(SlicePtr::len(ptr.as_ptr() as *const [u8]), 0);
            assert_eq!(num, libc::SYS_exit as _);
            assert_eq!(argv, [5, 0, 0, 0, 0, 0]);
            assert_eq!(ret, [-libc::ENOSYS as _, 0]);
            true
        }));
    }
}
