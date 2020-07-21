// SPDX-License-Identifier: Apache-2.0

//! This crate implements an SGX version of an Enarx keep.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod builder;
mod enclave;
mod layout;

use builder::{Builder, Segment};
use enclave::Leaf;
use loader::{segment, Component};

use bounds::Span;
use intel_types::Exception;
use memory::Page;
use sallyport::Block;
use sgx::types::{
    page::{Flags, SecInfo},
    tcs::Tcs,
};
use structopt::StructOpt;

use std::path::PathBuf;

#[derive(Debug, StructOpt)]
#[structopt(name = "enarx-keep-sgx", about = "Launches an Enarx Keep on SGX.")]
struct Opt {
    /// The SGX shim
    #[structopt(short, long, parse(from_os_str))]
    shim: PathBuf,

    /// The code to run
    #[structopt(short, long, parse(from_os_str))]
    code: PathBuf,
}

fn load() -> enclave::Enclave {
    let opt = Opt::from_args();

    // Parse the shim and code and validate assumptions.
    let shim = Component::from_path(opt.shim).expect("Unable to parse shim");
    let mut code = Component::from_path(opt.code).expect("Unable to parse code");
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
            si: SecInfo::reg(Flags::R | Flags::W | Flags::X),
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

    let to_si_seg = |s: segment::Segment| {
        let mut rwx = Flags::empty();

        if s.perms.read {
            rwx |= Flags::R;
        }
        if s.perms.write {
            rwx |= Flags::W;
        }
        if s.perms.execute {
            rwx |= Flags::X;
        }

        Segment {
            si: SecInfo::reg(rwx),
            dst: s.dst,
            src: s.src,
        }
    };

    let shim_segs: Vec<Segment> = shim.segments.into_iter().map(to_si_seg).collect();
    let code_segs: Vec<Segment> = code.segments.into_iter().map(to_si_seg).collect();

    // Initiate the enclave building process.
    let mut builder = Builder::new(layout.enclave).expect("Unable to create builder");
    builder.load(&internal).unwrap();
    builder.load(&shim_segs).unwrap();
    builder.load(&code_segs).unwrap();
    builder.done(layout.prefix.start).unwrap()
}

fn main() {
    let enclave = load();

    let mut block = Block::default();

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
        match enclave.enter(&mut block as *const _ as _, 0, 0, Leaf::Enter, 0, 0) {
            // On InvalidOpcode: re-enter the enclave with EENTER (CSSA++).
            Err(Some(ei)) if ei.trap == Exception::InvalidOpcode => (),

            // We don't currently know how to handle other AEX events.
            e => panic!("Unexpected AEX: {:?}", e),
        }
    }
}
