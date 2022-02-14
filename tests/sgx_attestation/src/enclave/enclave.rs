// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, RwLock};

use mmarinus::{perms, Map};
use primordial::Register;

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
#[derive(Copy, Clone)]
pub struct ExceptionInfo {
    /// Last entry type
    pub last: Entry,

    /// Exception error code
    pub trap: Exception,

    /// Trapping code
    pub code: u16,

    /// Memory address where exception occurred
    pub addr: Address<u64>,
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
    _mem: Map<perms::Unknown>,
    tcs: Vec<*mut Tcs>,
}

impl Enclave {
    // Use `sgx::enclave::Builder::build` to create a new SGX `Enclave`
    // instance.
    pub(super) fn new(mem: Map<perms::Unknown>, tcs: Vec<*mut Tcs>) -> Self {
        Self { _mem: mem, tcs }
    }
}

/// The registers that can be passed to/from the enclave
#[repr(C)]
#[derive(Default, Debug)]
#[allow(missing_docs)]
pub struct Registers {
    pub rdi: Register<usize>,
    pub rsi: Register<usize>,
    pub rdx: Register<usize>,
    pub r8: Register<usize>,
    pub r9: Register<usize>,
}

// This structure is dictated by the Linux kernel.
//
// See: https://github.com/torvalds/linux/blob/84292fffc2468125632a21c09533a89426ea212e/arch/x86/include/uapi/asm/sgx.h#L112
#[repr(C)]
#[derive(Default, Debug)]
struct Run {
    tcs: Register<u64>,
    function: u32,
    exception_vector: u16,
    exception_error_code: u16,
    exception_addr: Register<u64>,
    user_handler: Register<u64>,
    user_data: Register<u64>,
    reserved: [u64; 27],
}

// This function signature is dictated by the Linux kernel.
//
// See: https://github.com/torvalds/linux/blob/84292fffc2468125632a21c09533a89426ea212e/arch/x86/include/uapi/asm/sgx.h#L92
extern "C" fn handler(
    rdi: Register<usize>,
    rsi: Register<usize>,
    rdx: Register<usize>,
    _rsp: Register<usize>,
    r8: Register<usize>,
    r9: Register<usize>,
    run: &mut Run,
) -> libc::c_int {
    let registers: *mut Registers = run.user_data.into();
    let registers: &mut Registers = unsafe { &mut *registers };
    registers.rdi = rdi;
    registers.rsi = rsi;
    registers.rdx = rdx;
    registers.r8 = r8;
    registers.r9 = r9;
    0
}

/// A single thread of execution inside an enclave.
pub struct Thread {
    enc: Arc<RwLock<Enclave>>,
    tcs: *mut Tcs,
    fnc: unsafe extern "C" fn(
        rdi: Register<usize>,
        rsi: Register<usize>,
        rdx: Register<usize>,
        leaf: Entry,
        r8: Register<usize>,
        r9: Register<usize>,
        run: &mut Run,
    ) -> libc::c_int,
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
        let fnc = unsafe { core::mem::transmute(fnc) };

        Some(Self { enc, tcs, fnc })
    }

    /// Enter an enclave.
    ///
    /// This function enters an enclave using `Entry` and provides the
    /// specified `registers` to the enclave. On success, the `registers`
    /// variable contains the registers returned from the enclave. Otherwise,
    /// an asynchronous exit (AEX) has occurred and the details about the
    /// exception are returned.
    #[inline(always)]
    pub fn enter(&mut self, how: Entry, registers: &mut Registers) -> Result<(), ExceptionInfo> {
        let mut run = Run {
            tcs: self.tcs.into(),
            user_handler: (handler as usize).into(),
            user_data: registers.into(),
            ..Default::default()
        };

        // The `enclu` instruction consumes `rax`, `rbx` and `rcx`. However,
        // the vDSO function preserves `rbx` AND sets `rax` as the return
        // value. All other registers are passed to and from the enclave
        // unmodified.
        //
        // Therefore, we use `rdx` to pass a single argument into and out from
        // the enclave. We consider all other registers to be clobbered by the
        // enclave itself.
        let rax: i32;
        unsafe {
            asm!(
                "push rbx",       // save rbx
                "push rbp",       // save rbp
                "mov  rbp, rsp",  // save rsp
                "and  rsp, ~0xf", // align to 16+0

                "push 0",         // align to 16+8
                "push r10",       // push run address
                "call r11",       // call vDSO function

                "mov  rsp, rbp",  // restore rsp
                "pop  rbp",       // restore rbp
                "pop  rbx",       // restore rbx

                inout("rdi") usize::from(registers.rdi) => _,
                inout("rsi") usize::from(registers.rsi) => _,
                inout("rdx") usize::from(registers.rdx) => _,
                inout("rcx") how as u32 => _,
                inout("r8") usize::from(registers.r8) => _,
                inout("r9") usize::from(registers.r9) => _,
                inout("r10") &mut run => _,
                inout("r11") self.fnc => _,
                lateout("r12") _,
                lateout("r13") _,
                lateout("r14") _,
                lateout("r15") _,
                lateout("rax") rax,
            );
        }

        match (rax, run.function) {
            (0, 4) => return Ok(()),
            (0, 2) | (0, 3) => (),
            _ => unreachable!(),
        }

        Err(ExceptionInfo {
            trap: unsafe { core::mem::transmute(run.exception_vector as u8) },
            code: run.exception_error_code,
            addr: Address(run.exception_addr.into()),
            last: unsafe { core::mem::transmute(run.function) },
        })
    }
}
