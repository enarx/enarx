// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

musl_fsbase_fix!();

fn main() {
    println!("Start");

    use std::sync::mpsc::channel;
    use std::thread;

    let (tx, rx) = channel();

    let sender = thread::spawn(move || {
        tx.send("Hello, thread".to_owned())
            .expect("Unable to send on channel");
    });

    let receiver = thread::spawn(move || {
        let value = rx.recv().expect("Unable to receive from channel");
        println!("{value}");
    });

    sender.join().expect("The sender thread has panicked");
    receiver.join().expect("The receiver thread has panicked");
}
