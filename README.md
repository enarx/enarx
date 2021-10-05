![lint](https://github.com/enarx/enarx/workflows/lint/badge.svg)
![enarxbot](https://github.com/enarx/enarx/workflows/enarxbot/badge.svg)
[![Workflow Status](https://github.com/enarx/enarx/workflows/test/badge.svg)](https://github.com/enarx/enarx/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/enarx.svg)](https://isitmaintained.com/project/enarx/enarx "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/enarx.svg)](https://isitmaintained.com/project/enarx/enarx "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# enarx

This crate provides the `enarx` executable which loads `static-pie`
binaries into an Enarx Keep - that is a hardware isolated environment using
technologies such as Intel SGX or AMD SEV.

## Building

Please see **BUILD.md** for instructions.

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
    $ target/debug/enarx exec ./test
    Hello World!

## Select a Different Backend

`enarx exec` will probe the machine it is running on
in an attempt to deduce an appropriate deployment backend unless
that target is already specified in an environment variable
called `ENARX_BACKEND`.

To see what backends are supported on your system, run:

    $ target/debug/enarx info

To manually select a backend, set the `ENARX_BACKEND` environment
variable:

    $ ENARX_BACKEND=sgx target/debug/enarx exec ./test

Note that some backends are conditionally compiled. They can all
be compiled in like so:

    $ cargo build --all-features

Or specific backends can be compiled in:

    $ cargo build --features=backend-sgx,backend-kvm

License: Apache-2.0
