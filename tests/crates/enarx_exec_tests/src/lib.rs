// SPDX-License-Identifier: Apache-2.0

//! musl_fsbase_fix

use der::Sequence;
use x509_cert::crl::CertificateList;

#[macro_export]
macro_rules! musl_fsbase_fix {
    () => {
        /// Set FSBASE
        ///
        /// Overwrite the only location in musl, which uses the `arch_prctl` syscall
        #[cfg(all(target_arch = "x86_64",  target_vendor = "unknown", target_os = "linux", target_env = "musl"))]
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn __set_thread_area(p: *mut core::ffi::c_void) -> core::ffi::c_int {
            let mut rax: usize = 0;
            if unsafe { core::arch::x86_64::__cpuid(7).ebx } & 1 == 1 {
                unsafe {
                    core::arch::asm!("wrfsbase {}", in(reg) p);
                }
            } else {
                const ARCH_SET_FS: core::ffi::c_int = 0x1002;
                unsafe {
                    core::arch::asm!(
                    "syscall",
                    inlateout("rax")  libc::SYS_arch_prctl => rax,
                    in("rdi") ARCH_SET_FS,
                    in("rsi") p,
                    lateout("rcx") _, // clobbered
                    lateout("r11") _, // clobbered
                    );
                }
            }
            rax as _
        }
    }
}

// These structures are copied from `src/caching.rs`
#[derive(Debug, Sequence)]
pub struct CrlListEntry {
    pub url: String,
    pub crl: CertificateList,
}

#[derive(Debug, Sequence)]
pub struct CrlList {
    pub crls: Vec<CrlListEntry>,
}
