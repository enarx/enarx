// SPDX-License-Identifier: Apache-2.0

use super::{enarxcall, gdbcall, syscall, Item, Kind, LARGEST_ITEM_SIZE};

use core::convert::TryInto;
use core::mem::{align_of, size_of};

/// Untrusted `sallyport` block.
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Block<'a>(&'a mut [usize]);

impl<'a> Block<'a> {
    /// Returns the approximate length (of `usize` elements) of the block required to fit
    /// `item_count` items of biggest size and `data_size` bytes of allocated data.
    /// Note, that this function does not account for alignment of the allocated data,
    /// and therefore this is merely a hint and not a precise calculation.
    #[allow(clippy::question_mark)] // `?` is not supported in `const` functions.
    pub const fn size_hint(item_count: usize, data_size: usize) -> Option<usize> {
        let item_size = if let Some(item_size) = item_count.checked_mul(LARGEST_ITEM_SIZE) {
            item_size
        } else {
            return None;
        };

        let size = if let Some(size) = item_size.checked_add(data_size) {
            size
        } else {
            return None;
        };

        let count = size / size_of::<usize>();
        if size % size_of::<usize>() == 0 {
            Some(count)
        } else {
            Some(count + 1)
        }
    }
}

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
                        decode_item::<{ syscall::USIZE_COUNT }, syscall::Payload>(*size, tail)
                            .map(|((call, data), tail)| (Some(Item::Syscall(call, data)), tail))
                    }

                    Ok(Kind::Gdbcall) => {
                        decode_item::<{ gdbcall::USIZE_COUNT }, gdbcall::Payload>(*size, tail)
                            .map(|((call, data), tail)| (Some(Item::Gdbcall(call, data)), tail))
                    }

                    Ok(Kind::Enarxcall) => {
                        decode_item::<{ enarxcall::USIZE_COUNT }, enarxcall::Payload>(*size, tail)
                            .map(|((call, data), tail)| (Some(Item::Enarxcall(call, data)), tail))
                    }

                    Err(_) => Some((None, tail.split_at_mut(*size / size_of::<usize>()).1.into())),
                }
            }
            _ => None,
        }
    }
}

impl<'a> IntoIterator for Block<'a> {
    type Item = Item<'a>;
    type IntoIter = BlockIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        BlockIterator(Some(self))
    }
}

/// An iterator for `Item` over a `Block`
pub struct BlockIterator<'a>(Option<Block<'a>>);

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.take() {
            Some(mut block) => loop {
                match block.into() {
                    Some((Some(item), tail)) => {
                        self.0 = Some(tail);
                        return Some(item);
                    }
                    Some((None, tail)) => {
                        block = tail;
                    }
                    None => return None,
                }
            },
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Header;
    use crate::libc::{SYS_exit, SYS_read, ENOSYS};

    const HEADER_USIZE_COUNT: usize = size_of::<Header>() / size_of::<usize>();

    #[test]
    fn block_size_hint() {
        const LARGEST_ITEM_USIZE_COUNT: usize = syscall::USIZE_COUNT;
        assert_eq!(
            Block::size_hint(1, 42 * size_of::<usize>()),
            Some(HEADER_USIZE_COUNT + LARGEST_ITEM_USIZE_COUNT + 42),
        );
        assert_eq!(
            Block::size_hint(2, 42 * size_of::<usize>() - 2),
            Some(2 * HEADER_USIZE_COUNT + 2 * LARGEST_ITEM_USIZE_COUNT + 42),
        )
    }

    #[test]
    fn block() {
        let mut block: [usize; 3 * HEADER_USIZE_COUNT + 2 * syscall::USIZE_COUNT + 1] = [
            (syscall::USIZE_COUNT + 1) * size_of::<usize>(), // size
            Kind::Syscall as _,                              // kind
            SYS_read as _,                                   // num
            1,                                               // fd
            0,                                               // buf
            4,                                               // count
            0,                                               // -
            0,                                               // -
            0,                                               // -
            -ENOSYS as _,                                    // ret
            0,                                               // -
            0xdeadbeef,                                      // data
            /* --------------------- */
            syscall::USIZE_COUNT * size_of::<usize>(), // size
            Kind::Syscall as _,                        // kind
            SYS_exit as _,                             // num
            5,                                         // status
            0,                                         // -
            0,                                         // -
            0,                                         // -
            0,                                         // -
            0,                                         // -
            -ENOSYS as _,                              // ret
            0,                                         // -
            /* --------------------- */
            0,              // size
            Kind::End as _, // kind
        ];

        let block = Block::from(&mut block[..]);
        let mut block_iter = block.into_iter();

        let item = block_iter.next().unwrap();
        assert!(
            matches!(item, Item::Syscall (syscall::Payload{ num, argv, ret }, data) if {
                assert_eq!(*num, SYS_read as _);
                assert_eq!(*argv, [1, 0, 4, 0, 0, 0]);
                assert_eq!(*ret, [-ENOSYS as _, 0]);
                assert_eq!(data, [0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0]);
                true
            })
        );

        let item = block_iter.next().unwrap();
        assert!(
            matches!(item, Item::Syscall (syscall::Payload{ num, argv, ret }, data) if {
                assert_eq!(*num, SYS_exit as _);
                assert_eq!(*argv, [5, 0, 0, 0, 0, 0]);
                assert_eq!(*ret, [-ENOSYS as _, 0]);
                assert_eq!(data, []);
                true
            })
        );
        assert!(block_iter.next().is_none());
    }
}
