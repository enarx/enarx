// SPDX-License-Identifier: Apache-2.0

//! Host-specific functionality.

#[cfg(not(miri))]
mod enarxcall;
#[cfg(not(miri))]
mod syscall;

use crate::item::Item;
use crate::libc::{EFAULT, EOVERFLOW};
use crate::Result;

use core::mem::{align_of, size_of};
use core::ptr::slice_from_raw_parts_mut;

pub(super) trait Execute {
    unsafe fn execute(self) -> Result<()>;
}

impl<'a> Execute for Item<'a> {
    #[inline]
    unsafe fn execute(self) -> Result<()> {
        match self {
            #[cfg(not(miri))]
            Item::Syscall(call, data) => syscall::execute(call, data),
            #[cfg(miri)]
            Item::Syscall { .. } => Ok(()),

            Item::Gdbcall { .. } => Ok(()),

            #[cfg(not(miri))]
            Item::Enarxcall(call, data) => enarxcall::execute(call, data),
            #[cfg(miri)]
            Item::Enarxcall { .. } => Ok(()),
        }
    }
}

impl<'a, T: IntoIterator<Item = Item<'a>>> Execute for T {
    #[inline]
    unsafe fn execute(self) -> Result<()> {
        self.into_iter().try_for_each(|item| item.execute())
    }
}

/// Executes the passed `items`.
#[inline]
pub fn execute<'a>(items: impl IntoIterator<Item = Item<'a>>) -> Result<()> {
    unsafe { items.execute() }
}

/// Validates that `data` contains `len` elements of type `T` at `offset`
/// and returns a mutable pointer to the first element on success.
///
/// # Safety
///
/// Callers must ensure that pointer is correctly aligned before accessing it.
///
#[inline]
pub unsafe fn deref<T>(data: &mut [u8], offset: usize, len: usize) -> Result<*mut T> {
    let size = len.checked_mul(size_of::<T>()).ok_or(EOVERFLOW)?;
    if size > data.len() || data.len() - size < offset {
        Err(EFAULT)
    } else {
        Ok(data[offset..offset + size].as_mut_ptr() as _)
    }
}

/// Validates that `data` contains `len` elements of type `T` at `offset`
/// and returns a mutable slice pointer to the first element on success.
///
/// # Safety
///
/// Callers must ensure that pointer is correctly aligned before accessing it.
///
#[inline]
pub unsafe fn deref_slice<T>(data: &mut [u8], offset: usize, len: usize) -> Result<*mut [T]> {
    deref(data, offset, len).map(|ptr| slice_from_raw_parts_mut(ptr, len))
}

/// Validates that `data` contains `len` elements of type `T` at `offset`
/// aligned to `align_of::<T>()` and returns a mutable pointer to the first element on success.
#[inline]
pub fn deref_aligned<T>(data: &mut [u8], offset: usize, len: usize) -> Result<*mut T> {
    let ptr = unsafe { deref::<T>(data, offset, len) }?;
    if ptr.align_offset(align_of::<T>()) != 0 {
        Err(EFAULT)
    } else {
        Ok(ptr)
    }
}

/// Validates that `data` contains `len` elements of type `T` at `offset`
/// aligned to `align_of::<T>()` and returns a mutable slice pointer to the first element on success.
#[inline]
pub fn deref_aligned_slice<T>(data: &mut [u8], offset: usize, len: usize) -> Result<*mut [T]> {
    deref_aligned(data, offset, len).map(|ptr| slice_from_raw_parts_mut(ptr, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{gdbcall, Gdbcall, Syscall};
    use crate::NULL;

    use libc::{
        SYS_close, SYS_dup2, SYS_fcntl, SYS_read, SYS_sync, SYS_write, EFAULT, ENOSYS, EOVERFLOW,
        F_GETFD, STDIN_FILENO, STDOUT_FILENO,
    };
    use std::fmt::Debug;

    struct DerefTestCase<T> {
        offset: usize,
        len: usize,
        expected: T,
    }

    impl<T> From<(usize, usize, T)> for DerefTestCase<T> {
        fn from((offset, len, expected): (usize, usize, T)) -> Self {
            Self {
                offset,
                len,
                expected,
            }
        }
    }

    fn test_deref<T: Debug + PartialEq>(
        f: impl Fn(&mut [u8], usize, usize) -> T,
        data: &mut [u8],
        cases: impl IntoIterator<Item = impl Into<DerefTestCase<T>>>,
    ) {
        cases.into_iter().enumerate().for_each(|(i, case)| {
            let case = case.into();
            assert_eq!(
                f(data, case.offset, case.len),
                case.expected,
                "case: {}, data: {:?}",
                i,
                data.as_mut_ptr(),
            );
        })
    }

    #[test]
    fn deref() {
        let mut data = [0u8; 4];
        let cases = [
            (0, 0, Ok(data.as_mut_ptr() as _)),
            (0, 1, Ok(data.as_mut_ptr() as _)),
            (0, 2, Ok(data.as_mut_ptr() as _)),
            (0, 3, Err(EFAULT)),
            (1, 0, Ok(data[1..].as_mut_ptr() as _)),
            (1, 1, Ok(data[1..].as_mut_ptr() as _)),
            (1, 2, Err(EFAULT)),
            (2, 0, Ok(data[2..].as_mut_ptr() as _)),
            (2, 1, Ok(data[2..].as_mut_ptr() as _)),
            (2, 2, Err(EFAULT)),
            (usize::MAX, 0, Err(EFAULT)),
            (0, usize::MAX, Err(EOVERFLOW)),
            (usize::MAX, usize::MAX, Err(EOVERFLOW)),
        ];
        test_deref(
            |data, offset, len| unsafe { super::deref::<[u8; 2]>(data, offset, len) },
            &mut data,
            cases,
        );
        test_deref(
            |data, offset, len| super::deref_aligned::<[u8; 2]>(data, offset, len),
            &mut data,
            cases,
        );
    }

    #[test]
    fn deref_aligned() {
        let mut data = [0u128; 4];
        let (prefix, data, suffix) = unsafe { data.align_to_mut() };
        assert!(prefix.is_empty());
        assert!(suffix.is_empty());

        let cases = [
            (0, 0, Ok(data.as_mut_ptr() as _)),
            (0, 1, Ok(data.as_mut_ptr() as _)),
            (0, 2, Ok(data.as_mut_ptr() as _)),
            (1, 0, Err(EFAULT)),
            (1, 1, Err(EFAULT)),
            (1, 2, Err(EFAULT)),
            (2, 0, Ok(data[2..].as_mut_ptr() as _)),
            (2, 1, Ok(data[2..].as_mut_ptr() as _)),
            (2, 2, Ok(data[2..].as_mut_ptr() as _)),
            (usize::MAX, 0, Err(EFAULT)),
            (0, usize::MAX, Err(EOVERFLOW)),
            (usize::MAX, usize::MAX, Err(EOVERFLOW)),
        ];
        test_deref(
            |data, offset, len| super::deref_aligned::<u16>(data, offset, len),
            data,
            cases,
        );
    }

    #[test]
    fn deref_slice() {
        let mut data = [0u8; 4];
        let cases = [
            (
                0,
                0,
                Ok(slice_from_raw_parts_mut(data.as_mut_ptr() as _, 0)),
            ),
            (
                0,
                1,
                Ok(slice_from_raw_parts_mut(data.as_mut_ptr() as _, 1)),
            ),
            (
                0,
                2,
                Ok(slice_from_raw_parts_mut(data.as_mut_ptr() as _, 2)),
            ),
            (0, 3, Err(EFAULT)),
            (
                1,
                0,
                Ok(slice_from_raw_parts_mut(data[1..].as_mut_ptr() as _, 0)),
            ),
            (
                1,
                1,
                Ok(slice_from_raw_parts_mut(data[1..].as_mut_ptr() as _, 1)),
            ),
            (1, 2, Err(EFAULT)),
            (
                2,
                0,
                Ok(slice_from_raw_parts_mut(data[2..].as_mut_ptr() as _, 0)),
            ),
            (
                2,
                1,
                Ok(slice_from_raw_parts_mut(data[2..].as_mut_ptr() as _, 1)),
            ),
            (2, 2, Err(EFAULT)),
            (usize::MAX, 0, Err(EFAULT)),
            (0, usize::MAX, Err(EOVERFLOW)),
            (usize::MAX, usize::MAX, Err(EOVERFLOW)),
        ];
        test_deref(
            |data, offset, len| unsafe { super::deref_slice::<[u8; 2]>(data, offset, len) },
            &mut data,
            cases,
        );
        test_deref(
            |data, offset, len| super::deref_aligned_slice::<[u8; 2]>(data, offset, len),
            &mut data,
            cases,
        );
    }

    #[test]
    fn deref_aligned_slice() {
        let mut data = [0u128; 4];
        let (prefix, data, suffix) = unsafe { data.align_to_mut() };
        assert!(prefix.is_empty());
        assert!(suffix.is_empty());

        let cases = [
            (
                0,
                0,
                Ok(slice_from_raw_parts_mut(data.as_mut_ptr() as _, 0)),
            ),
            (
                0,
                1,
                Ok(slice_from_raw_parts_mut(data.as_mut_ptr() as _, 1)),
            ),
            (
                0,
                2,
                Ok(slice_from_raw_parts_mut(data.as_mut_ptr() as _, 2)),
            ),
            (1, 0, Err(EFAULT)),
            (1, 1, Err(EFAULT)),
            (1, 2, Err(EFAULT)),
            (
                2,
                0,
                Ok(slice_from_raw_parts_mut(data[2..].as_mut_ptr() as _, 0)),
            ),
            (
                2,
                1,
                Ok(slice_from_raw_parts_mut(data[2..].as_mut_ptr() as _, 1)),
            ),
            (
                2,
                2,
                Ok(slice_from_raw_parts_mut(data[2..].as_mut_ptr() as _, 2)),
            ),
            (usize::MAX, 0, Err(EFAULT)),
            (0, usize::MAX, Err(EOVERFLOW)),
            (usize::MAX, usize::MAX, Err(EOVERFLOW)),
        ];
        test_deref(
            |data, offset, len| super::deref_aligned_slice::<u16>(data, offset, len),
            data,
            cases,
        );
    }

    #[test]
    fn execute() {
        let fd = 42;
        let mut syscalls = [
            (
                Syscall {
                    num: SYS_dup2 as _,
                    argv: [STDIN_FILENO as _, fd, NULL, NULL, NULL, NULL],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_fcntl as _,
                    argv: [fd, F_GETFD as _, NULL, NULL, NULL, NULL],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_read as _,
                    argv: [fd, 0, 0, NULL, NULL, NULL],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_sync as _,
                    argv: [NULL, NULL, NULL, NULL, NULL, NULL],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_write as _,
                    argv: [STDOUT_FILENO as _, 0, 0, NULL, NULL, NULL],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_close as _,
                    argv: [fd, NULL, NULL, NULL, NULL, NULL],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
        ];
        let (dup2, tail) = syscalls.split_first_mut().unwrap();
        let (fcntl, tail) = tail.split_first_mut().unwrap();
        let (read, tail) = tail.split_first_mut().unwrap();
        let (sync, tail) = tail.split_first_mut().unwrap();
        let (write, tail) = tail.split_first_mut().unwrap();
        let (close, _) = tail.split_first_mut().unwrap();

        assert_eq!(
            super::execute(
                [
                    Item::Gdbcall(
                        &mut Gdbcall {
                            num: gdbcall::Number::Read,
                            argv: [NULL, NULL, NULL, NULL],
                            ret: -ENOSYS as _,
                        },
                        &mut [],
                    ),
                    Item::Syscall(&mut dup2.0, &mut dup2.1),
                    Item::Syscall(&mut fcntl.0, &mut fcntl.1),
                    Item::Syscall(&mut read.0, &mut read.1),
                    Item::Syscall(&mut sync.0, &mut sync.1),
                    Item::Syscall(&mut write.0, &mut write.1),
                    Item::Syscall(&mut close.0, &mut close.1),
                ]
                .into_iter()
                .filter_map(|item| match item {
                    Item::Gdbcall(call, data) => {
                        assert_eq!(
                            *call,
                            Gdbcall {
                                num: gdbcall::Number::Read,
                                argv: [NULL, NULL, NULL, NULL],
                                ret: -ENOSYS as _,
                            }
                        );
                        assert_eq!(*data, []);
                        call.ret = 42;
                        None
                    }
                    _ => Some(item),
                }),
            ),
            Ok(())
        );
        assert_eq!(
            syscalls,
            [
                (
                    Syscall {
                        num: SYS_dup2 as _,
                        argv: [STDIN_FILENO as _, fd, NULL, NULL, NULL, NULL],
                        #[cfg(not(miri))]
                        ret: [fd, 0],
                        #[cfg(miri)]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_fcntl as _,
                        argv: [fd as _, F_GETFD as _, NULL, NULL, NULL, NULL],
                        #[cfg(not(miri))]
                        ret: [0, 0],
                        #[cfg(miri)]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_read as _,
                        argv: [fd as _, 0, 0, NULL, NULL, NULL],
                        #[cfg(not(miri))]
                        ret: [0, 0],
                        #[cfg(miri)]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_sync as _,
                        argv: [NULL, NULL, NULL, NULL, NULL, NULL],
                        #[cfg(not(miri))]
                        ret: [0, 0],
                        #[cfg(miri)]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_write as _,
                        argv: [STDOUT_FILENO as _, 0, 0, NULL, NULL, NULL],
                        #[cfg(not(miri))]
                        ret: [0, 0],
                        #[cfg(miri)]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_close as _,
                        argv: [fd as _, NULL, NULL, NULL, NULL, NULL],
                        #[cfg(not(miri))]
                        ret: [0, 0],
                        #[cfg(miri)]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
            ]
        );
    }
}
