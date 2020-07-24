// SPDX-License-Identifier: Apache-2.0

use enumerate::enumerate;
use intel_types::Exception;
use std::{fmt, mem::MaybeUninit};

use mmap::Unmap;

extern "C" {
    fn eenter(
        rdi: usize,
        rsi: usize,
        rdx: usize,
        leaf: Leaf,
        r8: usize,
        r9: usize,
        tcs: usize,
        exc: &mut ExceptionInfo,
        handler: Option<
            unsafe extern "C" fn(
                rdi: usize,
                rsi: usize,
                rdx: usize,
                ursp: usize,
                r8: usize,
                r9: usize,
                tcs: usize,
                ret: i32,
                exc: &ExceptionInfo,
            ) -> i32,
        >,
        vdso: usize,
    ) -> i32;
}

enumerate! {
    /// Opcodes for non-privileged SGX leaf functions
    ///
    /// TODO add more comprehensive docs
    #[derive(Copy, Clone)]
    pub enum Leaf: u32 {
        /// EAX = 2, `EENTER`
        Enter = 2,
        /// EAX = 3, `ERESUME`
        Resume = 3,
    }
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
    /// Leaf function where exception occurred
    pub leaf: Leaf,
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
            .field("leaf", &self.leaf)
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
    #[allow(dead_code)]
    mem: Unmap,
    tcs: usize,
    fnc: usize,
}

impl Enclave {
    // Use `sgx::enclave::Builder::build` to create a new SGX `Enclave`
    // instance.
    pub(super) fn new(mem: Unmap, tcs: usize) -> Self {
        let fnc = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found") as *const _ as _;

        Self { mem, tcs, fnc }
    }

    /// Issues `EENTER` instruction to the enclave.
    ///
    /// TODO add more comprehensive docs
    #[inline(always)]
    pub fn enter(
        &self,
        rdi: usize,
        rsi: usize,
        rdx: usize,
        leaf: Leaf,
        r8: usize,
        r9: usize,
    ) -> Result<(), Option<ExceptionInfo>> {
        const FAULT: i32 = -libc::EFAULT;
        const EEXIT: i32 = 0;

        #[allow(clippy::uninit_assumed_init)]
        let mut exc: ExceptionInfo = unsafe { MaybeUninit::uninit().assume_init() };

        let ret = unsafe {
            eenter(
                rdi, rsi, rdx, leaf, r8, r9, self.tcs, &mut exc, None, self.fnc,
            )
        };

        match ret {
            EEXIT => Ok(()),
            FAULT => Err(Some(exc)),
            _ => Err(None),
        }
    }
}
