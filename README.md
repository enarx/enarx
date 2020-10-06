[![Workflow Status](https://github.com/enarx/enarx-keepldr/workflows/test/badge.svg)](https://github.com/enarx/enarx-keepldr/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/enarx-keepldr.svg)](https://isitmaintained.com/project/enarx/enarx-keepldr "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/enarx-keepldr.svg)](https://isitmaintained.com/project/enarx/enarx-keepldr "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# enarx-keepldr

This crate provides the `enarx-keepldr` executable which loads `static-pie`
binaries into an Enarx Keep - that is a hardware isolated environment using
technologies such as Intel SGX or AMD SEV.

## Install Dependencies

### Fedora

    $ sudo dnf install git curl gcc pkg-config openssl-devel musl-gcc

### Debian / Ubuntu

    $ sudo apt update
    $ sudo apt install git curl gcc pkg-config libssl-dev musl-tools python3-minimal

## Install Rust, Nightly and the MUSL target

    $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    $ source $HOME/.cargo/env
    $ rustup toolchain install nightly --allow-downgrade -t x86_64-unknown-linux-musl

## Build

    $ git clone https://github.com/enarx/enarx-keepldr
    $ cd enarx-keepldr/
    $ cargo build

## Run Tests

    $ cargo test

## Build and Run an Application

    $ cat > test.c <<EOF
    #include <stdio.h>

    int main() {
        printf("Hello World!\n");
        return 0;
    }
    EOF

    $ musl-gcc -static-pie -fPIC -o test test.c
    $ target/debug/enarx-keepldr exec ./test
    Hello World!

License: Apache-2.0
