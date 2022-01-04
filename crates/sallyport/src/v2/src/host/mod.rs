// SPDX-License-Identifier: Apache-2.0

//! Host-specific functionality.

#[cfg(feature = "asm")]
mod syscall;

#[cfg(feature = "asm")]
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
            #[cfg(feature = "asm")]
            Item::Syscall(syscall, data) => {
                let _ = execute_syscall(syscall, data);
            }
            #[cfg(not(feature = "asm"))]
            Item::Syscall { .. } => {}
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
    use crate::item::Syscall;

    use libc::*;

    #[test]
    fn execute() {
        let mut syscalls = [
            (
                Syscall {
                    num: SYS_fcntl as _,
                    argv: [STDIN_FILENO as _, F_GETFD as _, 0, 0, 0, 0],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_read as _,
                    argv: [STDIN_FILENO as _, 0, 0, 0, 0, 0],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_write as _,
                    argv: [STDOUT_FILENO as _, 0, 0, 0, 0, 0],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
            (
                Syscall {
                    num: SYS_close as _,
                    argv: [STDIN_FILENO as _, 0, 0, 0, 0, 0],
                    ret: [-ENOSYS as _, 0],
                },
                [],
            ),
        ];
        let (fcntl, tail) = syscalls.split_first_mut().unwrap();
        let (read, tail) = tail.split_first_mut().unwrap();
        let (write, tail) = tail.split_first_mut().unwrap();
        let (close, _) = tail.split_first_mut().unwrap();
        super::execute([
            Item::Syscall(&mut fcntl.0, &mut fcntl.1),
            Item::Syscall(&mut read.0, &mut read.1),
            Item::Syscall(&mut write.0, &mut write.1),
            Item::Syscall(&mut close.0, &mut close.1),
        ]);
        assert_eq!(
            syscalls,
            [
                (
                    Syscall {
                        num: SYS_fcntl as _,
                        argv: [STDIN_FILENO as _, F_GETFD as _, 0, 0, 0, 0],
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_read as _,
                        argv: [STDIN_FILENO as _, 0, 0, 0, 0, 0],
                        #[cfg(feature = "asm")]
                        ret: [0, 0],
                        #[cfg(not(feature = "asm"))]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_write as _,
                        argv: [STDOUT_FILENO as _, 0, 0, 0, 0, 0],
                        #[cfg(feature = "asm")]
                        ret: [0, 0],
                        #[cfg(not(feature = "asm"))]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
                (
                    Syscall {
                        num: SYS_close as _,
                        argv: [STDIN_FILENO as _, 0, 0, 0, 0, 0],
                        #[cfg(feature = "asm")]
                        ret: [0, 0],
                        #[cfg(not(feature = "asm"))]
                        ret: [-ENOSYS as _, 0],
                    },
                    []
                ),
            ]
        );
    }
}
