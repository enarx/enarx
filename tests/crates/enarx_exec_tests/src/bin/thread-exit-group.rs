// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

use std::thread;

musl_fsbase_fix!();

fn main() {
    println!("Before Spawn");

    let thread1 = thread::spawn(|| {
        thread::sleep(std::time::Duration::from_secs(2));
        println!("Hello from Thread 1!");
    });
    println!("After Spawn 1");

    let thread2 = thread::spawn(|| {
        thread::sleep(std::time::Duration::from_secs(1));
        println!("Hello from Thread 2!");

        std::process::exit(0);
    });
    println!("After Spawn 2");

    thread1.join().unwrap();
    println!("After Join 1");

    thread2.join().unwrap();
    println!("After Join 2");
}
