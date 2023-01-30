// SPDX-License-Identifier: Apache-2.0

//! Thread handling

use crate::hostcall::{BlockGuard, HostCall};
use crate::syscall::SyscallStackFrameValue;

use alloc::collections::VecDeque;
use core::arch::asm;
use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use const_default::ConstDefault;
use sallyport::guest::ThreadLocalStorage;
use sallyport::libc::pid_t;
use spin::RwLock;
use x86_64::instructions::segmentation::{Segment64, GS};
use x86_64::registers::rflags;
use x86_64::VirtAddr;

/// Pickup new threads from the queue.
pub fn pickup_new_threads() -> ! {
    loop {
        let mut queue = NEW_THREAD_QUEUE.write();
        let thread = queue.pop_front();
        match thread {
            Some(thread) => {
                drop(queue);
                let tcb = TcbRefCell::from_gs_base();
                let mut tcb = tcb.borrow_mut();
                tcb.tid = thread.tid;
                tcb.clear_on_exit = thread.clear_on_exit;
                tcb.tls = ThreadLocalStorage::new();
                drop(tcb);
                unsafe { thread.regs.load_registers() }
            }
            None => {
                THREADS_FREE.fetch_add(1, Ordering::SeqCst);
                drop(queue);
                HostCall::exit_io(0);
            }
        }
        THREADS_FREE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A thread register state that is currently running.
///
/// The following registers cannot be restored, because they are
/// r11 = rflags
/// rcx = rip
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct GenPurposeRegs {
    /// rax
    pub rax: u64,
    /// rdx
    pub rdx: u64,
    /// rbx
    pub rbx: u64,
    /// rbp
    pub rbp: u64,
    /// rsi
    pub rsi: u64,
    /// rdi
    pub rdi: u64,
    /// r8
    pub r8: u64,
    /// r9
    pub r9: u64,
    /// r10
    pub r10: u64,
    /// r12
    pub r12: u64,
    /// r13
    pub r13: u64,
    /// r14
    pub r14: u64,
    /// r15
    pub r15: u64,
    /// rflags
    pub rflags: u64,
    /// fsbase
    pub fsbase: u64,
    /// gsbase
    pub gsbase: u64,
    /// rip
    pub rip: u64,
    /// rsp
    pub rsp: u64,
}

impl From<&SyscallStackFrameValue> for GenPurposeRegs {
    fn from(value: &SyscallStackFrameValue) -> Self {
        GenPurposeRegs {
            rax: value.rax,
            rdx: value.rdx,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rflags: value.r11,
            fsbase: 0,
            gsbase: 0,
            rsi: value.rsi,
            rdi: value.rdi,
            rbp: value.rbp,
            rsp: value.rsp,
            rbx: value.rbx,
            rip: value.rcx,
        }
    }
}

/// Describe the state of the new thread
#[derive(Clone, Copy, Debug)]
pub struct NewThreadFromRegisters {
    /// The registers to use for the new thread
    pub regs: GenPurposeRegs,
    /// The thread ID
    pub tid: pid_t,
    /// The address of a u32 to clear on exit
    pub clear_on_exit: Option<&'static AtomicU32>,
}

/// Queue of new threads to be picked up
pub static NEW_THREAD_QUEUE: RwLock<VecDeque<NewThreadFromRegisters>> =
    RwLock::new(VecDeque::new());

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
    /// Holds addresses of AtomicU32 to clear on exiting the thread
    pub clear_on_exit: Option<&'static AtomicU32>,
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
                clear_on_exit: None,
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

/// actual thread ID to be used for the next thread
pub static THREAD_ID_CNT: AtomicI32 = AtomicI32::new(1);

/// number of free threads
pub static THREADS_FREE: AtomicUsize = AtomicUsize::new(0);

/// Extend some trait with a method to load registers
pub trait LoadRegsExt {
    /// manually load the registers from the SSA
    ///
    /// # Safety
    ///
    /// The Caller has to ensure the integrity of the loaded registers.
    unsafe fn load_registers(&self) -> !;
}

impl LoadRegsExt for GenPurposeRegs {
    // r11 = rflags
    // rcx = rip
    unsafe fn load_registers(&self) -> ! {
        static XSAVE: xsave::XSave = <xsave::XSave as ConstDefault>::DEFAULT;

        asm!(
        "mov rsp, rax                        ", // switch stack pointer

        "mov rax, 0                          ",
        "mov ds,  rax                        ", // clear segment selector
        "mov es,  rax                        ", // clear segment selector
        "mov rdx, ~0                         ", // Set mask for xrstor in rdx
        "mov rax, ~0                         ", // Set mask for xrstor in rax
        "xrstor [rip + {XSAVE}]              ", // Clear xCPU state with synthetic state

        "pop rax                             ",
        "pop rdx                             ",
        "pop rbx                             ",
        "pop rbp                             ",
        "pop rsi                             ",
        "pop rdi                             ",
        "pop r8                              ",
        "pop r9                              ",
        "pop r10                             ",
        "pop r12                             ",
        "pop r13                             ",
        "pop r14                             ",
        "pop r15                             ",
        "pop r11                             ", // pop rflags
        "pop rcx                             ", // fsbase
        "wrfsbase rcx                        ",
        "pop rcx                             ", // gsbase
        "swapgs                              ",
        "lfence                              ",
        "wrgsbase rcx                        ",
        "pop rcx                             ", // rip
        "pop rsp                             ", // rsp
        "sysretq                             ",

        XSAVE = sym XSAVE,
        in("rax") self as *const _ as u64,

        options(noreturn)
        )
    }
}

/// Enter Ring 3
///
/// # Safety
///
/// Because the caller can give any `entry_point` and `stack_pointer`
/// including 0, this function is unsafe.
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn usermode(ip: u64, sp: u64) -> ! {
    let regs = GenPurposeRegs {
        rip: ip,
        rsp: sp,
        rflags: rflags::read().bits(),
        ..Default::default()
    };
    regs.load_registers()
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
