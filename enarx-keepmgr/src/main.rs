//! Crate docs

#![deny(missing_docs)]
#![deny(clippy::all)]
#![allow(clippy::identity_op)]

mod access;
mod binary;
mod drivers;
mod span;

fn main() {
    use binary::Binary;
    use drivers::{Driver, Event};
    use std::env::args;

    let mut event = {
        // Choose our driver (curently just Debug).
        let driver = drivers::debug::Debug::new(args().nth(1).unwrap());
        eprintln!("driver: {}", driver.name());

        // Load and parse our shim and runtime binaries.
        let shim = std::fs::read(driver.shim().unwrap()).unwrap();
        let runt = std::fs::read(args().nth(1).unwrap()).unwrap();
        let shim = Binary::parse(&shim).unwrap();
        let runt = Binary::parse(&runt).unwrap();

        // Execute the state machine to create the keep.
        let keep = driver.make().unwrap();
        let keep = shim.load(keep).unwrap();
        let keep = runt.load(keep).unwrap();
        let keep = shim.load(keep).unwrap();
        let keep = runt.load(keep).unwrap();

        // Enter the keep for the first time.
        keep.enter(()).unwrap()
    };

    loop {
        event = match event {
            Event::exit(status) => std::process::exit(status),
            Event::getuid(keep) => keep.enter(unsafe { libc::getuid() }).unwrap(),
        }
    }
}
