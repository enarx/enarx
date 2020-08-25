// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};
use std::{fmt, mem::MaybeUninit};

use lset::Span;
use memory::Register;
use mmap::Unmap;

use crate::types::ssa::Exception;
use crate::types::tcs::Tcs;

/// How to enter an enclave
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Entry {
    /// Enter an enclave normally
    Enter = 2,

    /// Resume an enclave after an asynchronous exit
    Resume = 3,
}

/// Memory address where exception occurred.
///
/// TODO add more comprehensive docs
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Address<T: Copy + fmt::LowerHex>(T);

impl<T: Copy + fmt::LowerHex> fmt::Debug for Address<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// This struct assigns u16 for the trap field. But it contains only exception
/// numbers, which are u8. Therefore, we don't use ExceptionInfo::unused.
///
/// TODO add more comprehensive docs
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExceptionInfo {
    /// Last entry type
    pub last: Entry,

    /// Exception error code
    pub trap: Exception,

    unused: u8,

    /// Trapping code
    pub code: u16,

    /// Memory address where exception occurred
    pub addr: Address<u64>,

    reserved: [u64; 2],
}

impl fmt::Debug for ExceptionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExceptionInfo")
            .field("last", &self.last)
            .field("trap", &self.trap)
            .field("code", &self.code)
            .field("addr", &self.addr)
            .finish()
    }
}

/// Represents a fully initialized enclave, i.e., after `EINIT` instruction
/// was issued and `MRENCLAVE` measurement is complete, and the enclave is
/// ready to start user code execution.
///
/// TODO add more comprehensive docs
pub struct Enclave {
    mem: Unmap,
    tcs: Vec<*mut Tcs>,
}

impl Enclave {
    // Use `sgx::enclave::Builder::build` to create a new SGX `Enclave`
    // instance.
    pub(super) fn new(mem: Unmap, tcs: Vec<*mut Tcs>) -> Self {
        Self { mem, tcs }
    }

    /// Get the memory region of the enclave
    pub fn span(&self) -> Span<usize> {
        self.mem.span()
    }
}

/// A single thread of execution inside an enclave.
pub struct Thread {
    enc: Arc<RwLock<Enclave>>,
    tcs: *mut Tcs,
    fnc: &'static vdso::Symbol,
}

impl Drop for Thread {
    fn drop(&mut self) {
        self.enc.write().unwrap().tcs.push(self.tcs)
    }
}

impl Thread {
    /// Create a new thread of execuation for an enclave.
    pub fn new(enc: Arc<RwLock<Enclave>>) -> Option<Self> {
        let tcs = enc.write().unwrap().tcs.pop()?;

        let fnc = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found");

        Some(Self { enc, tcs, fnc })
    }

    /// Enter an enclave.
    ///
    /// This function enters an enclave using `Entry` and provides the
    /// specified argument to the enclave in the `rdx` register. On success,
    /// the value of the `rdx` register at enclave exit is returned. There
    /// are two failure cases. If the enclave performs an asynchronous exit
    /// (AEX), the details of the exception are returned. Otherwise, an
    /// unknown error has occurred.
    #[inline(always)]
    pub fn enter(
        &self,
        how: Entry,
        arg: impl Into<Register<usize>>,
    ) -> Result<Register<usize>, Option<ExceptionInfo>> {
        const FAULT: i32 = -libc::EFAULT;
        const EEXIT: i32 = 0;

        let mut exc = MaybeUninit::<ExceptionInfo>::uninit();
        let mut rdx: usize = arg.into().into();
        let rax: i32;

        // The `enclu` instruction consumes `rax`, `rbx` and `rcx`. However,
        // the vDSO function preserves `rbx` AND sets `rax` as the return
        // value. All other registers are passed to and from the enclave
        // unmodified.
        //
        // Therefore, we use `rdx` to pass a single argument into and out from
        // the enclave. We consider all other registers to be clobbered by the
        // enclave itself.
        unsafe {
            asm!(
                "push rbp",       // save rbp
                "mov  rbp, rsp",  // save rsp
                "and  rsp, ~0xf", // align to 16+0

                "push 0",         // align to 16+8
                "push 0",         // push exit handler arg
                "push {}",        // push exception info arg
                "push {}",        // push tcs page address arg
                "call {}",        // call vDSO function

                "mov  rsp, rbp",  // restore rsp
                "pop  rbp",       // restore rbp

                in(reg) exc.as_mut_ptr(),
                in(reg) self.tcs,
                in(reg) self.fnc,
                inout("rdx") rdx,
                inout("rcx") how as u32 => _,
                lateout("rax") rax,
                lateout("rdi") _,
                lateout("rsi") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r11") _,
                lateout("r12") _,
                lateout("r13") _,
                lateout("r14") _,
                lateout("r15") _,
            );
        }

        match rax {
            EEXIT => Ok(rdx.into()),
            FAULT => Err(Some(unsafe { exc.assume_init() })),
            _ => Err(None),
        }
    }
}
