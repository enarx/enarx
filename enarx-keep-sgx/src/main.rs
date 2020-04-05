// SPDX-License-Identifier: Apache-2.0

//! This crate implements an SGX version of an Enarx keep.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod builder;
mod component;
mod enclave;
mod layout;
mod map;

use builder::Builder;
use component::{Component, Segment};
use enclave::Leaf;

use intel_types::Exception;
use memory::Page;
use sgx_types::page::{Flags, SecInfo};
use sgx_types::tcs::Tcs;
use span::Span;

fn load() -> enclave::Enclave {
    const USAGE: &str = "Usage: enarx-keep-sgx <shim> <code>";

    // Get the arguments.
    let mut args = std::env::args();
    let shim = args.nth(1).expect(USAGE);
    let code = args.next().expect(USAGE);

    // Parse the shim and code and validate assumptions.
    let shim = Component::from_path(shim).expect("Unable to parse shim");
    let mut code = Component::from_path(code).expect("Unable to parse code");
    assert!(!shim.pie);
    assert!(code.pie);

    // Calculate the memory layout for the enclave.
    let layout = layout::Layout::calculate(shim.region(), code.region());

    // Relocate the code binary.
    code.entry += layout.code.start;
    for seg in code.segments.iter_mut() {
        seg.dst += layout.code.start;
    }

    // Create SSAs and TCS.
    let ssas = vec![Page::default(); 2];
    let tcs = Tcs::new(
        shim.entry - layout.enclave.start,
        Page::size() * 2, // SSAs after Layout (see below)
        ssas.len() as _,
    );

    let internal = vec![
        // TCS
        Segment {
            si: SecInfo::tcs(),
            dst: layout.prefix.start,
            src: vec![Page::copy(tcs)],
        },
        // Layout
        Segment {
            si: SecInfo::reg(Flags::R),
            dst: layout.prefix.start + Page::size(),
            src: vec![Page::copy(layout)],
        },
        // SSAs
        Segment {
            si: SecInfo::reg(Flags::R | Flags::W),
            dst: layout.prefix.start + Page::size() * 2,
            src: ssas,
        },
        // Heap
        Segment {
            si: SecInfo::reg(Flags::R | Flags::W),
            dst: layout.heap.start,
            src: vec![Page::default(); Span::from(layout.heap).count / Page::size()],
        },
        // Stack
        Segment {
            si: SecInfo::reg(Flags::R | Flags::W),
            dst: layout.stack.start,
            src: vec![Page::default(); Span::from(layout.stack).count / Page::size()],
        },
    ];

    // Initiate the enclave building process.
    let mut builder = Builder::new(layout.enclave).expect("Unable to create builder");
    builder.load(&internal).unwrap();
    builder.load(&shim.segments).unwrap();
    builder.load(&code.segments).unwrap();
    builder.done(layout.prefix.start).unwrap()
}

fn main() {
    let enclave = load();

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
        match enclave.enter(0, 0, 0, Leaf::Enter, 0, 0) {
            // On InvalidOpcode: re-enter the enclave with EENTER (CSSA++).
            Err(Some(ei)) if ei.trap == Exception::InvalidOpcode => (),

            // We don't currently know how to handle other AEX events.
            e => panic!("Unexpected AEX: {:?}", e),
        }
    }
}
