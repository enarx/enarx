// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::musl_fsbase_fix;

musl_fsbase_fix!();

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

static GLOBAL_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

fn main() {
    for i in 0..100 {
        GLOBAL_THREAD_COUNT.fetch_add(1, Ordering::SeqCst);

        thread::spawn(move || {
            // do some work
            eprintln!("{}-th thread reporting", i + 1);
            thread::sleep(Duration::from_secs(1));
            GLOBAL_THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
        });
    }

    let mut i = 0;

    while GLOBAL_THREAD_COUNT.load(Ordering::SeqCst) != 0 {
        i += 1;
        if i > 100 {
            eprintln!(
                "{} threads still running",
                GLOBAL_THREAD_COUNT.load(Ordering::SeqCst)
            );
            std::process::exit(1);
        }
        thread::sleep(Duration::from_millis(100));
    }
}
