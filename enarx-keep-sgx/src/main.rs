// SPDX-License-Identifier: Apache-2.0

//! foo

#![deny(clippy::all)]
#![deny(missing_docs)]

mod builder;
mod component;
mod convert;
mod paged;

use addr::{Address, Offset};
use enarx_keep::{Event, Keep, Start};
use span::Span;
use units::bytes;

use std::io::Result;

extern "C" {
    #[no_mangle]
    fn enarx_eenter(tcs: Address<usize>);
}

type Bounds = Span<Address<usize>, Offset<usize>>;

#[allow(dead_code)]
struct Enclave {
    tcs: Address<usize>,
    mem: mmap::Mapping,
}

impl Keep<Start> for Enclave {
    fn enter(self: Box<Self>, _: Start) -> Result<Event> {
        eprintln!("base: {:x}", self.tcs.inner());
        unsafe { enarx_eenter(self.tcs) };
        Ok(Event::getuid(self))
    }
}

impl Keep<libc::uid_t> for Enclave {
    fn enter(self: Box<Self>, uid: libc::uid_t) -> Result<Event> {
        eprintln!("uid: {}", uid);
        Ok(Event::exit(0))
    }
}

fn main() {
    const USAGE: &str = "Usage: enarx-keep-sgx <shim> <code>";

    /// The size of the enclave was chosen because it appears to be the
    /// smallest maximum enclave size supported by 64-bit enclaves on
    /// Intel chips in the wild. We are aiming for the largest universally
    /// available enclave size.
    ///
    /// The location of the enclave was chosen according to the following
    /// criteria.
    ///
    ///   1. Enclaves need to be naturally aligned. That is, their starting
    ///      position needs to be a multiple of the size. We want the freedom
    ///      to increase the default enclave size in the future. So that means
    ///      we need to choose the highest practical location for the base of
    ///      the enclave. Therefore, an enclave loaded at the 32TiB location
    ///      can be a maximum of 32TiB in size.
    ///
    ///   2. Increasing to 64TiB would put the end of the enclave at 128TiB.
    ///      However, the kernel sometimes loads data in this area. Therefore,
    ///      32TiB gives us maximum possible room to grow.
    const ENCLAVE: Bounds = Bounds {
        start: Address::new(bytes![32; TiB]),
        count: Offset::new(bytes![64; GiB]),
    };

    enarx_keep::main({
        // Get the arguments.
        let mut args = std::env::args();
        let shim = args.nth(1).expect(USAGE);
        let code = args.nth(0).expect(USAGE);

        // Parse the shim and code and validate assumptions.
        let shim = component::Component::from_path(shim).unwrap();
        let code = component::Component::from_path(code).unwrap();

        // Build the enclave.
        builder::Builder::build(ENCLAVE, shim, code).unwrap()
    })
}
