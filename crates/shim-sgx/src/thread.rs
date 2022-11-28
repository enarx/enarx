// SPDX-License-Identifier: Apache-2.0

//! Thread handling

use core::arch::asm;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicU32};
use primordial::Page;

use crate::{CSSA_0_STACK_SIZE, CSSA_1_PLUS_STACK_SIZE, NUM_SSA};
use sallyport::guest::ThreadLocalStorage;
use sallyport::libc::pid_t;
use sgx::ssa::{GenPurposeRegs, StateSaveArea};
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
pub struct NewThreadFromRegisters {
    /// The registers to use for the new thread
    pub regs: GenPurposeRegs,
    /// The thread ID
    pub tid: pid_t,
    /// The address of a u32 to clear on exit
    pub clear_on_exit: usize,
}

/// Describe the state of the new thread
#[derive(Clone, Copy, Debug)]
pub enum NewThread {
    /// The main thread starting the payload
    Main,
    /// A new thread with the given registers
    Thread(NewThreadFromRegisters),
}

/// Queue of new threads to be picked up
pub static NEW_THREAD_QUEUE: Lazy<RwLock<ConstVecDequeue<10, NewThread>>> = Lazy::new(|| {
    let mut queue = ConstVecDequeue::default();
    queue.push(NewThread::Main).unwrap();
    RwLock::new(queue)
});

/// SGX Thread Control Structure
///
/// Section 37.8
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct Tcs {
    /// Enclave execution state of the thread controlled by this TCS. A value of 0
    /// indicates that this TCS is available for enclave entry. A value of 1 indicates
    /// that a processer is currently executing an enclave in the context of this TCS.
    pub stage: u64,
    /// The thread’s execution flags.
    pub flags: TcsFlags,
    /// Offset of the base of the State Save Area stack, relative to the enclave base.
    /// Must be page aligned.
    pub ossa: u64,
    /// Current slot index of an SSA frame, cleared by EADD and EACCEPT.
    pub cssa: u32,
    /// Number of available slots for SSA frames.
    pub nssa: u32,
    /// Offset in enclave to which control is transferred on EENTER relative to
    /// the base of the enclave.
    pub oentry: u64,
    /// The value of the Asynchronous Exit Pointer that was saved at EENTER time.
    pub aep: u64,
    /// Offset to add to the base address of the enclave for producing the base
    /// address of FS segment inside the enclave. Must be page aligned
    pub ofsbase: u64,
    /// Offset to add to the base address of the enclave for producing the base
    /// address of GS segment inside the enclave. Must be page aligned
    pub ogsbase: u64,
    /// Size to become the new FS limit in 32-bit mode.
    pub fslimit: u32,
    /// Size to become the new GS limit in 32-bit mode.
    pub gslimit: u32,
    /// When CPUID.(EAX=12H, ECX=1):EAX[6] is 1, this field provides the offset of
    /// the CET state save area from enclave base. When CPUID.(EAX=12H,
    /// ECX=1):EAX[6] is 0, this field is reserved and must be 0.
    pub ocetssa: u64,
    /// When CPUID.(EAX=07H, ECX=00h):ECX[CET_SS] is 1, this field records the SSP
    /// at the time of AEX or EEXIT; used to setup SSP on entry. When
    /// CPUID.(EAX=07H, ECX=00h):ECX[CET_SS] is 0, this field is reserved and must
    /// be 0.
    pub prevssp: u64,
    _reserved: [u8; 4008],
}

bitflags::bitflags! {
    /// The thread’s execution flags.
    #[derive(Default)]
    pub struct TcsFlags: u64 {
        /// If set, allows debugging features (single-stepping, breakpoints, etc.)
        /// to be enabled and active while executing in the enclave on this TCS.
        /// Hardware clears this bit on EADD. A debugger may later modify it if the
        /// enclave’s ATTRIBUTES.DEBUG is set.
        const DBGOPTIN = 1 << 0;
        /// A thread that enters the enclave cannot receive AEX notifications
        /// unless this flag is set.
        const AEXNOTIFY = 1 << 1;
    }
}

impl Default for Tcs {
    fn default() -> Self {
        Self {
            stage: 0,
            flags: Default::default(),
            ossa: 0,
            cssa: 0,
            nssa: 0,
            oentry: 0,
            aep: 0,
            ofsbase: 0,
            ogsbase: 0,
            fslimit: 0,
            gslimit: 0,
            ocetssa: 0,
            prevssp: 0,
            _reserved: [0; 4008],
        }
    }
}

/// Enarx Thread Memory layout
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct ThreadMem {
    /// Stack for CSSA > 0.
    pub cssa_stack: [u8; CSSA_1_PLUS_STACK_SIZE],
    /// Stack for CSSA = 0
    pub stack: [u8; CSSA_0_STACK_SIZE],
    /// Enarx thread control block.
    tcb: [u8; Page::SIZE],
    /// SGX thread control structure.
    pub tcs: Tcs,
    /// State save area.
    pub ssa: [StateSaveArea; NUM_SSA],
}

/// Return to main
#[derive(Default)]
#[repr(C)]
pub struct ReturnToMain {
    /// FS base
    pub fsbase: u64,
    /// GS base
    pub gsbase: u64,
    /// rbp
    pub rbp: u64,
    /// rbx
    pub rbx: u64,
    /// rip
    pub rip: u64,
    /// rsp
    pub rsp: u64,
}

/// Thread Control Block
#[derive(Default)]
pub struct Tcb {
    /// State to return to CSSA[0]
    pub return_to_main: ReturnToMain,
    /// The thread ID
    pub tid: pid_t,
    /// Holds addresses of AtomicU32 to clear on exiting the thread
    pub clear_on_exit: Option<NonNull<AtomicU32>>,
    /// sallyport thread local storage
    pub tls: ThreadLocalStorage,
}

/// actual thread ID to be used for the next thread
pub static THREAD_ID_CNT: AtomicI32 = AtomicI32::new(1);

/// number of free threads
pub static THREADS_FREE: RwLock<usize> = RwLock::new(0);

/// Extend some trait with a method to load registers
pub trait LoadRegsExt {
    /// manually load the registers from the SSA
    ///
    /// # Safety
    ///
    /// The Caller has to ensure the integrity of the loaded registers.
    unsafe fn load_registers(&self, tcb: &mut Tcb) -> i32;
}

impl LoadRegsExt for GenPurposeRegs {
    unsafe fn load_registers(&self, tcb: &mut Tcb) -> i32 {
        let ret: i32;

        asm!(
            "rdfsbase rcx                        ",
            "mov [rdx + 0*8], rcx                ", // tcb.fsbase
            "rdgsbase rcx                        ",
            "mov [rdx + 1*8], rcx                ", // tcb.gsbase
            "mov [rdx + 2*8], rbp                ", // tcb.rbp
            "mov [rdx + 3*8], rbx                ", // tcb.rbx
            "lea rcx,         [rip + 2f]         ",
            "mov [rdx + 4*8], rcx                ", // tcb.rip = label 2
            "mov [rdx + 5*8], rsp                ", // tcb.rsp
            "mov rsp, rax                        ", // switch stack pointer
            "pop rax                             ", // skip rax
            "pop rcx                             ",
            "pop rdx                             ",
            "pop rbx                             ",
            "pop rax                             ", // skip rsp
            "pop rbp                             ",
            "pop rsi                             ",
            "pop rdi                             ",
            "pop r8                              ",
            "pop r9                              ",
            "pop r10                             ",
            "pop r11                             ",
            "pop r12                             ",
            "pop r13                             ",
            "pop r14                             ",
            "pop r15                             ",
            "popfq                               ", // pop rflags
            "mov rax, QWORD PTR [rsp + 168 - 136]", // fsbase
            "wrfsbase rax                        ",
            "pop rax                             ", // rip
            "add rax, 2                          ", // skip syscall
            "mov rsp, QWORD PTR [rsp + 32 - 144] ", // rsp
            "push rax                            ", // push rip
            "mov rax, 0                          ", // clone child has 0 in ret
            "ret                                 ", // return to rip
            "2:                                  ", // return point for exit

            inout("rax") self as *const _ as u64 => _,
            lateout("ecx") ret,
            lateout("r15") _,
            lateout("r14") _,
            lateout("r13") _,
            lateout("r12") _,
            lateout("r11") _,
            lateout("r10") _,
            lateout("r9") _,
            lateout("r8") _ ,
            lateout("rdi") _,
            lateout("rsi") _,
            inout("rdx") &mut tcb.return_to_main as *mut _ as u64 => _,
        );
        ret
    }
}

#[cfg(test)]
mod test {
    use super::{ConstVecDequeue, Tcb, Tcs};
    use core::mem::size_of;
    use primordial::Page;
    use testaso::testaso;

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

    #[test]
    fn test_thread_control_block() {
        assert!(size_of::<Tcb>() < Page::SIZE);
    }

    testaso! {
        struct Tcs: 4096, 4096 => {
            prevssp: 80,
            _reserved: 88
        }
    }
}
