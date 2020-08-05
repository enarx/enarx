// SPDX-License-Identifier: Apache-2.0

use libc::clock_gettime;

fn main() {
    let mut ts = libc::timespec {
        tv_nsec: Default::default(),
        tv_sec: Default::default(),
    };

    unsafe {
        clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut _);
    }

    assert_ne!(ts.tv_sec, 0);
}
