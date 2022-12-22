// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

musl_fsbase_fix!();

#[cfg(target_os = "linux")]
fn main() {
    use std::io;
    use std::sync::atomic::AtomicU32;
    use std::time;

    let futex = AtomicU32::new(0);
    let futex_ptr = &futex as *const AtomicU32;
    let timespec = libc::timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };

    let now = time::Instant::now();
    let r = unsafe {
        libc::syscall(
            libc::SYS_futex,
            futex_ptr,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            0,
            &timespec as *const _,
        )
    };

    assert_eq!(r, -1);
    let err = io::Error::last_os_error().raw_os_error().unwrap();
    assert_eq!(err, libc::ETIMEDOUT);

    assert!(now.elapsed().as_secs() >= 2);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("only supported on Linux")
}
