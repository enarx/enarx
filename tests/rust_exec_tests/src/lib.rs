// SPDX-License-Identifier: Apache-2.0

//! musl_fsbase_fix

#[macro_export]
macro_rules! musl_fsbase_fix {
    () => {
        /// Set FSBASE
        ///
        /// Overwrite the only location in musl, which uses the `arch_prctl` syscall
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn __set_thread_area(p: *mut std::ffi::c_void) -> std::ffi::c_int {
            let mut rax: usize = 0;
            if unsafe { core::arch::x86_64::__cpuid(7).ebx } & 1 == 1 {
                unsafe {
                    std::arch::asm!("wrfsbase {}", in(reg) p);
                }
            } else {
                const ARCH_SET_FS: std::ffi::c_int = 0x1002;
                unsafe {
                    std::arch::asm!(
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
