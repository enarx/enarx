// SPDX-License-Identifier: Apache-2.0

//! This crate implements an SGX version of an Enarx keep.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod builder;
mod component;
mod enclave;
mod map;

use intel_types::Exception;
use sgx_types::page::SecInfo;
use span::Span;

use enclave::Leaf;

fn main() {
    const USAGE: &str = "Usage: enarx-keep-sgx <shim> <code>";

    let (enclave, entry) = {
        // Get the arguments.
        let mut args = std::env::args();
        let shim = args.nth(1).expect(USAGE);
        let code = args.next().expect(USAGE);

        // Parse the shim and code and validate assumptions.
        let shim = component::Component::from_path(shim).expect("Unable to parse shim");
        let code = component::Component::from_path(code).expect("Unable to parse code");

        // Determine the memory range for the enclave.
        let span: Span<_, _> = shim.range().into();
        let span = Span {
            start: span.start,
            count: span.count.next_power_of_two(),
        };

        // Initiate the enclave building process.
        let mut builder = builder::Builder::new(span).expect("Unable to create builder");

        // Load the shim segments.
        for seg in shim.segments.iter() {
            let mut src = unsafe { seg.src.align_to().1 };
            let mut off = seg.dst.start - span.start;

            // The first page of the shim entry is the TCS page.
            if seg.dst.start == shim.entry {
                builder
                    .load(&src[..4096], off, SecInfo::tcs())
                    .expect("Unable to add TCS page");
                src = &src[4096..];
                off += 4096;
            }

            if !src.is_empty() {
                builder
                    .load(src, off, SecInfo::reg(seg.rwx))
                    .expect("Unable to add shim page");
            }
        }

        // Load the code segments.
        for seg in code.segments.iter() {
            let src = unsafe { seg.src.align_to().1 };
            let off = seg.dst.start - span.start;
            builder
                .load(&src, off, SecInfo::reg(seg.rwx))
                .expect("Unable to add code page");
        }

        // Complete the process.
        (
            builder.done().expect("Unable to initialize enclave"),
            code.entry,
        )
    };

    // The main loop event handing is divided into two halves.
    //
    //   1. EEXIT events (including syscall proxying and ERESUMEs [CSSA--])
    //      are handled by the handler callback to the vDSO function. See
    //      enclave.rs and enclave.S. This allows us to pass registers
    //      directly to the syscall instruction.
    //
    //   2. Asynchronous exits (AEX) are handled here to minimize the amount
    //      of assembly code used.
    loop {
        match enclave.enter(entry, 0, 0, Leaf::Enter, 0, 0) {
            // On InvalidOpcode: re-enter the enclave with EENTER (CSSA++).
            Err(Some(ei)) if ei.trap == Exception::InvalidOpcode => (),

            // We don't currently know how to handle other AEX events.
            e => panic!("Unexpected AEX: {:?}", e),
        }
    }
}
