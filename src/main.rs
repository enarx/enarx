// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
// protobuf-codegen-pure would generate warnings
#![allow(elided_lifetimes_in_paths)]

mod backend;
mod cli;
mod drawbridge;
mod exec;
#[cfg(enarx_with_shim)]
mod protobuf;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let app = cli::Options::parse();
    app.execute()
}
