// SPDX-License-Identifier: Apache-2.0

//! Thread handling

use crate::hostcall::BlockGuard;

use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use sallyport::guest::ThreadLocalStorage;
use sallyport::libc::pid_t;
use x86_64::instructions::segmentation::{Segment64, GS};
use x86_64::VirtAddr;

/// Thread Control Block
///
/// The first 2 elements are unsafely accessed by the syscall exception handler.
/// Because of this, they must be the first 2 elements in the struct.
/// It is sound, because the syscall exception handler is the only code that
/// accesses these elements and single threaded.
#[repr(C)]
pub struct Tcb {
    /// storage for the kernel stack
    /// private, because it is accessed via the gsbase in the syscall exception
    kernel_stack: VirtAddr,
    /// storage for the userspace stack
    /// private, because it is accessed via the gsbase in the syscall exception
    userspace_stack: VirtAddr,
    /// The thread ID
    pub tid: pid_t,
    /// sallyport thread local storage
    pub tls: ThreadLocalStorage,
    /// sallyport block,
    pub block: BlockGuard,
}

/// RefCell<Tcb> variant that is stored in the gsbase
///
/// Because `RefCell` is not repr(C) and the syscall exception asm needs
/// to access the first two fields, we need to use a custom struct.
#[repr(C)]
pub struct TcbRefCell {
    value: UnsafeCell<Tcb>,
    borrow: Cell<BorrowFlag>,
}

type BorrowFlag = isize;
const UNUSED: BorrowFlag = 0;

#[inline(always)]
fn is_writing(x: BorrowFlag) -> bool {
    x < UNUSED
}

/// core::cell::BorrowRefMut clone
struct TcbBorrowRefMut<'b> {
    borrow: &'b Cell<BorrowFlag>,
}

impl Drop for TcbBorrowRefMut<'_> {
    #[inline]
    fn drop(&mut self) {
        let borrow = self.borrow.get();
        debug_assert!(is_writing(borrow));
        self.borrow.set(borrow + 1);
    }
}

impl<'b> TcbBorrowRefMut<'b> {
    #[inline]
    fn new(borrow: &'b Cell<BorrowFlag>) -> Option<TcbBorrowRefMut<'b>> {
        // NOTE: Unlike BorrowRefMut::clone, new is called to create the initial
        // mutable reference, and so there must currently be no existing
        // references. Thus, while clone increments the mutable refcount, here
        // we explicitly only allow going from UNUSED to UNUSED - 1.
        match borrow.get() {
            UNUSED => {
                borrow.set(UNUSED - 1);
                Some(TcbBorrowRefMut { borrow })
            }
            _ => None,
        }
    }
}

/// A wrapper type for a mutably borrowed value from a `TcbRefCell<T>`.
///
/// core::cell::RefMut clone
pub struct TcbRefMut<'b, T: ?Sized> {
    // NB: we use a pointer instead of `&'b mut T` to avoid `noalias` violations, because a
    // `RefMut` argument doesn't hold exclusivity for its whole scope, only until it drops.
    value: NonNull<T>,
    #[allow(dead_code)]
    borrow: TcbBorrowRefMut<'b>,
    // `NonNull` is covariant over `T`, so we need to reintroduce invariance.
    marker: PhantomData<&'b mut T>,
}

impl<T: ?Sized> Deref for TcbRefMut<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: the value is accessible as long as we hold our borrow.
        unsafe { self.value.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for TcbRefMut<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the value is accessible as long as we hold our borrow.
        unsafe { self.value.as_mut() }
    }
}

impl TcbRefCell {
    /// Create a new TCB
    pub fn new(kernel_stack: VirtAddr, block: BlockGuard) -> Self {
        Self {
            value: UnsafeCell::new(Tcb {
                kernel_stack,
                userspace_stack: VirtAddr::zero(),
                tid: 0,
                tls: Default::default(),
                block,
            }),
            borrow: Cell::new(UNUSED),
        }
    }

    /// Get a mutable reference to the TCB
    ///
    /// panics if the TCB is already borrowed
    pub fn borrow_mut(&self) -> TcbRefMut<'_, Tcb> {
        match TcbBorrowRefMut::new(&self.borrow) {
            Some(b) => {
                // SAFETY: `TcbBorrowRefMut` guarantees unique access.
                let value = unsafe { NonNull::new_unchecked(self.value.get()) };
                TcbRefMut {
                    value,
                    borrow: b,
                    marker: PhantomData,
                }
            }
            None => panic!("try_borrow_mut: already mutably borrowed"),
        }
    }

    /// Get a mutable reference to the CPU local Tcb.
    pub fn from_gs_base() -> &'static TcbRefCell {
        let base = GS::read_base();
        let base = NonNull::new(base.as_u64() as _).unwrap();
        // SAFETY:
        // the GS base is set to the initialized TcbRefCell.
        // The pointer is properly aligned.
        // It is be "dereferenceable".
        // The pointer points to an initialized instance of TcbRefCell.
        // The lifetime is static and only per cpu.
        let tcb = unsafe { base.as_ref() };
        tcb
    }
}

#[cfg(test)]
mod test {
    use super::Tcb;
    use core::mem::size_of;
    use primordial::Page;

    #[test]
    fn test_thread_control_block() {
        assert!(size_of::<Tcb>() < Page::SIZE);
    }
}
