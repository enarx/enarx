# Building

## Install Dependencies

### Fedora

    $ sudo dnf install git curl gcc pkg-config openssl-devel musl-gcc

### Disclaimer

Please note that most (all) Enarx developers use Fedora, so that is the
distribution where we'll be able to offer most support, if any.

The following configurations are unlikely to be exercised with any
frequency and as a result, may not work for you. However, they have
worked at some point in the past and therefore they are listed here
in the hopes that they might be useful to you.

Please feel free to file a pull request to add your favorite distribution
if you're able to build and run the `enarx-keepldr` test suite.

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
