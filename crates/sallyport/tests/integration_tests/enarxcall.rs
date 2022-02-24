// SPDX-License-Identifier: Apache-2.0

use super::run_test;

use libc::ENOSYS;
use std::arch::x86_64::{CpuidResult, __cpuid_count};

use sallyport::guest::Handler;

#[test]
fn balloon_memory() {
    run_test(1, [0xff; 16], move |_, handler| {
        assert_eq!(handler.balloon_memory(1, 2, 0xfeed as _), Err(ENOSYS));
    })
}

#[test]
#[cfg_attr(miri, ignore)]
fn cpuid() {
    run_test(1, [0xff; 16], move |_, handler| {
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
fn mem_info() {
    run_test(1, [0xff; 16], move |_, handler| {
        assert_eq!(handler.mem_info(), Err(ENOSYS));
    })
}
