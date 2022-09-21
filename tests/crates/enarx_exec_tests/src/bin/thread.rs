// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

use std::thread;

musl_fsbase_fix!();

fn main() {
    for _ in 0..2 {
        println!("Before Spawn");

        let thread1 = thread::spawn(|| {
            thread::sleep(std::time::Duration::from_secs(2));
            println!("Hello from Thread 1!");
            0
        });
        println!("After Spawn 1");

        let thread2 = thread::spawn(|| {
            thread::sleep(std::time::Duration::from_secs(1));
            println!("Hello from Thread 2!");
            0
        });
        println!("After Spawn 2");

        let ret: i32 = thread1.join().unwrap();
        assert_eq!(ret, 0);
        println!("After Join 1");

        let ret: i32 = thread2.join().unwrap();
        assert_eq!(ret, 0);
        println!("After Join 2");

        // Wait for threads to be returned to the thread pool
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
