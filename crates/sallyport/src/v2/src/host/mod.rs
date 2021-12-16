// SPDX-License-Identifier: Apache-2.0

//! Host-specific functionality.

#[cfg(feature = "asm")]
mod syscall;

#[cfg(feature = "asm")]
use syscall::*;

use crate::item::Item;

pub(super) trait Execute {
    unsafe fn execute(self);
}

impl<'a> Execute for Item<'a> {
    #[inline]
    unsafe fn execute(self) {
        match self {
            #[cfg(feature = "asm")]
            Item::Syscall { ptr, .. } => {
                let _ = execute_syscall(ptr);
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

    use core::marker::PhantomData;
    use core::ptr::{slice_from_raw_parts_mut, NonNull};
    use libc::{SYS_fcntl, SYS_read, ENOSYS, F_GETFD, STDIN_FILENO};

    #[test]
    fn execute() {
        let mut syscalls = [
            Syscall {
                num: SYS_read as _,
                argv: [STDIN_FILENO as _, 0, 0, 0, 0, 0],
                ret: [-ENOSYS as _, 0],
            },
            Syscall {
                num: SYS_fcntl as _,
                argv: [STDIN_FILENO as _, F_GETFD as _, 0, 0, 0, 0],
                ret: [-ENOSYS as _, 0],
            },
        ];
        super::execute([
            Item::Syscall {
                ptr: unsafe {
                    NonNull::new_unchecked(slice_from_raw_parts_mut(&mut syscalls[0] as _, 0) as _)
                },
                phantom: PhantomData,
            },
            Item::Syscall {
                ptr: unsafe {
                    NonNull::new_unchecked(slice_from_raw_parts_mut(&mut syscalls[1] as _, 0) as _)
                },
                phantom: PhantomData,
            },
        ]);
        assert_eq!(
            syscalls,
            [
                Syscall {
                    num: SYS_read as _,
                    argv: [STDIN_FILENO as _, 0, 0, 0, 0, 0],
                    ret: [-ENOSYS as _, 0],
                },
                Syscall {
                    num: SYS_fcntl as _,
                    argv: [STDIN_FILENO as _, F_GETFD as _, 0, 0, 0, 0],
                    ret: [-ENOSYS as _, 0],
                },
            ]
        );
    }
}
