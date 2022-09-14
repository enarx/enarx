// SPDX-License-Identifier: Apache-2.0

//! Thread handling

use core::arch::asm;
use core::sync::atomic::{AtomicI32, AtomicUsize};

use sgx::ssa::GenPurposeRegs;
use spinning::{Lazy, RwLock};

/// A constant array to enqueue and dequeue from.
#[derive(Clone, Debug)]
pub struct ConstVecDequeue<const N: usize, T: Sized + Copy> {
    records: [Option<T>; N],
    start: usize,
    count: usize,
}

impl<const N: usize, T: Sized + Copy> Default for ConstVecDequeue<N, T> {
    fn default() -> Self {
        Self {
            records: [None; N],
            start: 0,
            count: 0,
        }
    }
}

impl<const N: usize, T: Sized + Copy> ConstVecDequeue<N, T> {
    /// Push a record to the end of the queue.
    pub fn push(&mut self, val: T) -> Result<(), T> {
        if self.count >= N {
            return Err(val); // full
        }

        let end = (self.start + self.count) % N;
        self.records[end].replace(val);
        self.count += 1;
        Ok(())
    }

    /// Pop a record from the front of the queue.
    pub fn pop(&mut self) -> Option<T> {
        if self.count == 0 {
            return None;
        }

        let record = self.records[self.start].take();
        self.start = (self.start + 1) % N;
        self.count -= 1;

        record
    }
}

/// Describe the state of the new thread
#[derive(Clone, Copy, Debug)]
pub enum NewThread {
    /// The main thread starting the payload
    Main,
    /// A new thread with the given registers
    Thread((u32, GenPurposeRegs)),
}

/// Queue of new threads to be picked up
pub static NEW_THREAD_QUEUE: Lazy<RwLock<ConstVecDequeue<10, NewThread>>> = Lazy::new(|| {
    let mut queue = ConstVecDequeue::default();
    queue.push(NewThread::Main).unwrap();
    RwLock::new(queue)
});

/// Maximum number of threads
pub const MAX_THREADS: usize = 3;

/// actual thread ID
pub static NUM_THREADS: AtomicI32 = AtomicI32::new(1);

// this is only used in the initializer below
#[allow(clippy::declare_interior_mutable_const)]
const ZERO_ATOMIC_USIZE: AtomicUsize = AtomicUsize::new(0);

/// Holds addresses of AtomicU32 to clear on exiting the thread
pub static THREAD_CLEAR_TID: [AtomicUsize; MAX_THREADS] = [ZERO_ATOMIC_USIZE; MAX_THREADS];

/// Holds the addresses of the thread SSA frames
pub static THREAD_SSAS: [AtomicUsize; MAX_THREADS] = [ZERO_ATOMIC_USIZE; MAX_THREADS];

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
    unsafe fn load_registers(&self) -> ! {
        asm!(
            "mov rsp, {rsp}",
            "pop rax",                              // skip rax
            "pop rcx",
            "pop rdx",
            "pop rbx",
            "pop rax",                              // skip rsp
            "pop rbp",
            "pop rsi",
            "pop rdi",
            "pop r8",
            "pop r9",
            "pop r10",
            "pop r11",
            "pop r12",
            "pop r13",
            "pop r14",
            "pop r15",
            "popfq",                                // pop rflags
            "mov rax, QWORD PTR [rsp + 168 - 136]", // fsbase
            "wrfsbase rax",
            "pop rax",                              // rip
            "add rax, 2",                           // skip syscall
            "mov rsp, QWORD PTR [rsp + 32 - 144]",  // rsp
            "push rax",                             // push rip
            "mov rax, 0",                           // clone child has 0 in ret
            "ret",                                  // return to rip

            rsp = in(reg) self as *const _ as u64,
            options(noreturn)
        )
    }
}

#[cfg(test)]
mod test {
    use super::ConstVecDequeue;

    #[test]
    fn test_const_vec_dequeue() {
        let mut queue = ConstVecDequeue::<3, u32>::default();

        assert_eq!(queue.pop(), None);

        queue.push(1).unwrap();
        queue.push(2).unwrap();
        queue.push(3).unwrap();
        assert_eq!(queue.push(4).unwrap_err(), 4);

        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
    }
}
