// SPDX-License-Identifier: Apache-2.0

//! Host-specific functionality.

#[cfg(not(miri))]
mod syscall;

#[cfg(not(miri))]
use syscall::*;

use crate::item::Item;
use crate::iter::{IntoIterator, Iterator};

pub(super) trait Execute {
    unsafe fn execute(self);
}

impl<'a> Execute for Item<'a> {
    #[inline]
    unsafe fn execute(self) {
        match self {
            #[cfg(not(miri))]
            Item::Syscall(syscall, data) => {
                let _ = execute_syscall(syscall, data);
            }
            #[cfg(miri)]
            Item::Syscall { .. } => {}

            Item::Gdbcall { .. } => {}
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
            IntoIterator::into_iter([
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
            ])
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
