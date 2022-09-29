// SPDX-License-Identifier: Apache-2.0

use super::run_test;

use core::ptr::NonNull;
use libc::ENOSYS;
use std::arch::x86_64::{CpuidResult, __cpuid_count};

use sallyport::guest::Handler;
use sallyport::libc::timespec;

#[test]
fn balloon_memory() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.balloon_memory(1, 2, 0xfeed as _), Err(ENOSYS));
    })
}

#[test]
#[cfg_attr(miri, ignore)]
fn cpuid() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        let mut result = CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        assert_eq!(handler.cpuid(0, 0, &mut result), Ok(()));
        assert_eq!(result, unsafe { __cpuid_count(0, 0) })
    })
}

#[test]
fn get_sgx_quote() {
    run_test(1, [0xff; 1024], move |_, _, handler| {
        let report = Default::default();
        let mut quote = [0u8; 16];
        assert_eq!(handler.get_sgx_quote(&report, &mut quote), Err(ENOSYS));
    })
}

#[test]
fn get_snp_vcek() {
    run_test(1, [0xff; 512], move |_, _, handler| {
        let mut vcek = [0u8; 16];
        assert_eq!(handler.get_snp_vcek(&mut vcek), Err(ENOSYS));
    })
}

#[test]
fn get_sgx_target_info() {
    run_test(1, [0xff; 512], move |_, _, handler| {
        let mut info = Default::default();
        assert_eq!(handler.get_sgx_target_info(&mut info), Err(ENOSYS));
    })
}

#[test]
fn mem_info() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.mem_info(), Err(ENOSYS));
    })
}

#[test]
fn mmap_host() {
    run_test(2, [0xff; 16], move |_, _, handler| {
        assert_eq!(
            handler.mmap_host(NonNull::new(0x7f8af78eb000 as *mut _).unwrap(), 4096, 0),
            Err(ENOSYS)
        );
    })
}

#[test]
fn mprotect_host() {
    run_test(2, [0xff; 16], move |_, _, handler| {
        assert_eq!(
            handler.mprotect_host(NonNull::new(0x7f8af78eb000 as *mut _).unwrap(), 4096, 0),
            Err(ENOSYS)
        );
    })
}

#[test]
fn munmap_host() {
    run_test(2, [0xff; 16], move |_, _, handler| {
        assert_eq!(
            handler.munmap_host(NonNull::new(0x7f8af78eb000 as *mut _).unwrap(), 4096),
            Err(ENOSYS)
        );
    })
}

#[test]
fn spawn() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.spawn(0), Err(ENOSYS));
    })
}

#[test]
fn park() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        let timeout = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(handler.park(0, Some(&timeout)), Err(ENOSYS));
    })
}

#[test]
fn trim_sgx_pages() {
    run_test(2, [0xff; 16], move |_, _, handler| {
        assert_eq!(
            handler.modify_sgx_page_type(NonNull::new(0x7f8af78eb000 as *mut _).unwrap(), 4096, 1),
            Err(ENOSYS)
        );
    })
}

#[test]
fn unpark() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.unpark(), Err(ENOSYS));
    })
}
