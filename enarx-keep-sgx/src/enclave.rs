// SPDX-License-Identifier: Apache-2.0

use enumerate::enumerate;
use intel_types::Exception;
use std::mem::MaybeUninit;

use super::map::Unmap;

extern "C" {
    fn handle(
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

    fn eenter(
        rdi: usize,
        rsi: usize,
        rdx: usize,
        leaf: Leaf,
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
pub struct Address<T: Copy + std::fmt::LowerHex>(T);

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
    pub leaf: Leaf,
    pub trap: Exception,
    unused: u8,
    pub code: u16,
    pub addr: Address<u64>,
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
                rdi, rsi, rdx, leaf, r8, r9, self.tcs, &mut exc, handle, self.fnc,
            )
        };

        match ret {
            EEXIT => Ok(()),
            FAULT => Err(Some(exc)),
            _ => Err(None),
        }
    }
}
