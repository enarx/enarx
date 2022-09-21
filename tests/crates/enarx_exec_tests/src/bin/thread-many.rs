// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

use std::thread;

musl_fsbase_fix!();

fn main() {
    for _ in 0..100 {
        let thread1 = thread::spawn(|| 0);

        let thread2 = thread::spawn(|| 0);

        let ret: i32 = thread1.join().unwrap();
        assert_eq!(ret, 0);

        let ret: i32 = thread2.join().unwrap();
        assert_eq!(ret, 0);

        // Wait for threads to be returned to the thread pool
        thread::sleep(std::time::Duration::from_micros(100));
    }
}
