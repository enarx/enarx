// SPDX-License-Identifier: Apache-2.0

use enumerate::enumerate;
use intel_types::Exception;

use super::map::Unmap;

extern "C" {
    fn enclave_handle(
        rdi: usize,
        rsi: usize,
        rdx: usize,
        ursp: usize,
        r8: usize,
        r9: usize,
        tcs: usize,
        ret: i32,
        exc: &ExceptionInfo,
    ) -> i32;

    fn enclave_enter(
        rdi: usize,
        rsi: usize,
        rdx: usize,
        rcx: usize,
        r8: usize,
        r9: usize,
        tcs: usize,
        exc: &mut ExceptionInfo,
        handler: unsafe extern "C" fn(
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
        vdso: usize,
        cmd: Leaf,
    ) -> i32;
}

enumerate! {
    #[derive(Copy, Clone)]
    pub enum Leaf: u32 {
        Enter = 2,
        Resume = 3,
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct Address<T: Copy + std::fmt::LowerHex>(T);

impl<T: Copy + std::fmt::LowerHex> std::fmt::Debug for Address<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

// This struct assigns u16 for the trap field. But it contains only exception
// numbers, which are u8. Therefore, we don't use ExceptionInfo::unused.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExceptionInfo {
    leaf: Leaf,
    trap: Exception,
    unused: u8,
    code: u16,
    addr: Address<u64>,
    reserved: [u64; 2],
}

impl std::fmt::Debug for ExceptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExceptionInfo")
            .field("leaf", &self.leaf)
            .field("trap", &self.trap)
            .field("code", &self.code)
            .field("addr", &self.addr)
            .finish()
    }
}

pub struct Enclave {
    #[allow(dead_code)]
    mem: Unmap,
    tcs: usize,
    fnc: usize,
}

impl Enclave {
    pub fn new(mem: Unmap, tcs: usize) -> Self {
        let fnc = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found") as *const _ as _;

        Self { mem, tcs, fnc }
    }

    #[inline(always)]
    pub fn enter(&self, leaf: Leaf) -> Result<(), Option<ExceptionInfo>> {
        const FAULT: i32 = -libc::EFAULT;
        const EEXIT: i32 = 0;

        #[allow(clippy::uninit_assumed_init)]
        let mut exc: ExceptionInfo = unsafe { std::mem::MaybeUninit::uninit().assume_init() };

        match unsafe {
            enclave_enter(
                0,
                0,
                0,
                0,
                0,
                0,
                self.tcs,
                &mut exc,
                enclave_handle,
                self.fnc,
                leaf,
            )
        } {
            EEXIT => Ok(()),
            FAULT => Err(Some(exc)),
            _ => Err(None),
        }
    }
}
