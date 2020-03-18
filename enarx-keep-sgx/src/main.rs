// SPDX-License-Identifier: Apache-2.0

//! This crate implements an SGX version of an Enarx keep.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod builder;
mod component;
mod contents;
mod enclave;
mod map;
mod page;

use sgx_types::page::SecInfo;
use span::Span;

use enclave::Leaf;

fn main() {
    const USAGE: &str = "Usage: enarx-keep-sgx <shim> <code>";

    let enclave = {
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
            let mut src = seg.src.as_ref();
            let mut off = seg.dst.start - span.start;

            // The first page of the shim entry is the TCS page.
            if seg.dst.start == shim.entry {
                builder
                    .load(&src[..4096], off, SecInfo::tcs())
                    .expect("Unable to add TCS page");
                src = &src[4096..];
                off += 4096;
            }

            builder
                .load(src, off, SecInfo::reg(seg.rwx))
                .expect("Unable to add shim page");
        }

        // Load the code segments.
        for seg in code.segments.iter() {
            let off = seg.dst.start - span.start;
            builder
                .load(&seg.src, off, SecInfo::reg(seg.rwx))
                .expect("Unable to add code page");
        }

        // Complete the process.
        builder.done().expect("Unable to initialize enclave")
    };

    let mut leaf = Leaf::Enter;
    let mut cssa = 0usize;
    loop {
        eprintln!("{}: {:?}", cssa, leaf);

        match enclave.enter(leaf) {
            Ok(_) => {
                eprintln!("{}: Exit", cssa);

                if cssa == 0 {
                    std::process::exit(0);
                }

                leaf = Leaf::Resume;
                cssa -= 1;
            }

            Err(Some(exc)) => {
                eprintln!("{}: {:?}", cssa, exc);

                if !exc.resume() {
                    std::process::exit(1);
                }

                leaf = Leaf::Enter;
                cssa += 1;
            }

            _ => panic!("Unexpected exit code!"),
        }
    }
}
