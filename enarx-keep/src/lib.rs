// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

pub struct Start;

/// A trait containing the function used to enter a keep
pub trait Keep<T> {
    /// Enter the keep with the provided input until the next event
    fn enter(self: Box<Self>, input: T) -> std::io::Result<Event>;
}

/// All possible keep events
#[allow(non_camel_case_types)]
pub enum Event {
    /// Exit the process with the supplied exit value
    exit(i32),

    /// Get the user identifier of the process
    getuid(Box<dyn Keep<libc::uid_t>>),
}

pub fn main(keep: Box<dyn Keep<Start>>) -> ! {
    let mut event = keep.enter(Start).unwrap();

    loop {
        event = match event {
            Event::exit(status) => std::process::exit(status),
            Event::getuid(keep) => keep.enter(unsafe { libc::getuid() }).unwrap(),
        }
    }
}
