// SPDX-License-Identifier: Apache-2.0

//! Host-specific functionality.

#[cfg(not(miri))]
mod enarxcall;
#[cfg(not(miri))]
mod syscall;

use crate::item::Item;
use crate::Result;

use core::mem::{align_of, size_of};
use libc::EFAULT;

pub(super) trait Execute {
    unsafe fn execute(self);
}

impl<'a> Execute for Item<'a> {
    #[inline]
    unsafe fn execute(self) {
        match self {
            #[cfg(not(miri))]
            Item::Syscall(call, data) => {
                let _ = syscall::execute(call, data);
            }
            #[cfg(miri)]
            Item::Syscall { .. } => {}

            Item::Gdbcall { .. } => {}

            #[cfg(not(miri))]
            Item::Enarxcall(call, data) => {
                let _ = enarxcall::execute(call, data);
            }
            #[cfg(miri)]
            Item::Enarxcall { .. } => {}
        }
    }
}

impl<'a, T: IntoIterator<Item = Item<'a>>> Execute for T {
    #[inline]
    unsafe fn execute(self) {
        self.into_iter().for_each(|item| item.execute())
    }
}

/// Executes the passed `items`.
#[inline]
pub fn execute<'a>(items: impl IntoIterator<Item = Item<'a>>) {
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
    let size = len * size_of::<T>();
    if size > data.len() || data.len() - size < offset {
        Err(libc::EFAULT)
    } else {
        Ok(data[offset..offset + size].as_mut_ptr() as _)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{gdbcall, Gdbcall, Syscall};
    use crate::NULL;

    use libc::*;

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
