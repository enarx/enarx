![lint](https://github.com/enarx/enarx/workflows/lint/badge.svg)
![enarxbot](https://github.com/enarx/enarx/workflows/enarxbot/badge.svg)
[![Workflow Status](https://github.com/enarx/enarx/workflows/test/badge.svg)](https://github.com/enarx/enarx/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/enarx.svg)](https://isitmaintained.com/project/enarx/enarx "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/enarx.svg)](https://isitmaintained.com/project/enarx/enarx "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# enarx

This crate provides the `enarx` executable, which is a tool for running
code inside an Enarx Keep - that is a hardware isolated environment using
technologies such as Intel SGX or AMD SEV.

## Building

Please see **BUILD.md** for instructions.

## Run Tests

    $ cargo test

## Build and run a WebAssembly module

    $ cargo init --bin hello-world
    $ cd hello-world
    $ echo 'fn main() { println!("Hello, Enarx!"); }' > src/main.rs
    $ cargo build --release --target=wasm32-wasi
    $ enarx run target/wasm32-wasi/release/hello-world.wasm
    Hello, Enarx!

## Select a Different Backend

`enarx` will probe the machine it is running on in an attempt to deduce an
appropriate deployment backend. To see what backends are supported on your
system, run:

    $ enarx info

You can manually select a backend with the `--backend` option, or by
setting the `ENARX_BACKEND` environment variable:

    $ enarx run --backend=sgx test.wasm
    $ ENARX_BACKEND=sgx enarx run test.wasm

Note that some backends are conditionally compiled. They can all
be compiled in like so:

    $ cargo build --all-features

Or specific backends can be compiled in:

    $ cargo build --features=backend-sgx,backend-kvm

License: Apache-2.0
