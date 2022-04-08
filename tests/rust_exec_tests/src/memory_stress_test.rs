// SPDX-License-Identifier: Apache-2.0

#![feature(core_ffi_c)]
use rust_exec_tests::musl_fsbase_fix;

musl_fsbase_fix!();

const SIZE_32M: usize = 1024 * 1024 * 32;

fn main() {
    let mut ret = 0;
    let mut size: usize = 1;
    while size < SIZE_32M {
        let mut vec = Vec::with_capacity(size);
        vec.push(0u8);
        ret += vec.pop().unwrap();
        size *= 2;
        drop(vec);
    }

    for _i in 0..100 {
        let mut vec = Vec::with_capacity(size);
        vec.push(0u8);
        ret += vec.pop().unwrap();
        drop(vec);
    }

    while size > 0 {
        let mut vec = Vec::with_capacity(size);
        vec.push(0u8);
        ret += vec.pop().unwrap();
        size /= 2;
        drop(vec);
    }

    std::process::exit(ret as _);
}
