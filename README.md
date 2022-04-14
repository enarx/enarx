[![Test Status](https://github.com/enarx/enarx/actions/workflows/test.yml/badge.svg)](https://github.com/enarx/enarx/actions/workflows/test.yml)
[![Bug Status](https://img.shields.io/github/issues-raw/enarx/enarx/bug)](https://github.com/enarx/enarx/labels/bug)
[![Maintenance Status](https://img.shields.io/github/commit-activity/y/enarx/enarx)](https://github.com/enarx/enarx/pulse)
[![Version Status](https://img.shields.io/crates/v/enarx)](https://crates.io/crates/enarx)
[![Coverage Status](https://codecov.io/gh/enarx/enarx/branch/main/graph/badge.svg?token=03QIZXNJ2Y)](https://codecov.io/gh/enarx/enarx)

# enarx

This crate provides the `enarx` executable, which is a tool for running
code inside an Enarx Keep - that is a hardware isolated environment using
technologies such as Intel SGX or AMD SEV.

For more information about the project and the technology used
visit the [Enarx Project home page](https://enarx.dev/).

## SGX and SEV machine setup

Please see
[this wiki page](https://github.com/enarx/enarx/wiki/Reproducible-builds-and-Machine-setup)
for instructions.

## Building and Testing Enarx

Please see [BUILD.md](https://github.com/enarx/enarx/blob/main/BUILD.md) for instructions.

## Installing Enarx

Please see
[this wiki page](https://github.com/enarx/enarx/wiki/Install-Enarx)
for instructions.

## Build and run a WebAssembly module

Install the Webassembly rust toolchain:

```sh
$ rustup target install wasm32-wasi
```

Create simple rust program:

```sh
$ cargo init --bin hello-world
$ cd hello-world
$ echo 'fn main() { println!("Hello, Enarx!"); }' > src/main.rs
$ cargo build --release --target=wasm32-wasi
```

Assuming you did install the `enarx` binary and have it in your `$PATH`, you can
now run the Webassembly program in an Enarx keep.

```sh
$ enarx run target/wasm32-wasi/release/hello-world.wasm
[…]
Hello, Enarx!
```

If you want to suppress the debug output, add `2>/dev/null`.

## Select a Different Backend

`enarx` will probe the machine it is running on in an attempt to deduce an
appropriate deployment backend. To see what backends are supported on your
system, run:

```sh
$ enarx info
```

You can manually select a backend with the `--backend` option, or by
setting the `ENARX_BACKEND` environment variable:

```sh
$ enarx run --backend=sgx target/wasm32-wasi/release/hello-world.wasm
$ ENARX_BACKEND=sgx enarx run target/wasm32-wasi/release/hello-world.wasm
```

License: Apache-2.0
