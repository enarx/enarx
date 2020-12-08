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

### A note on gcc

The minimum required `gcc` version is version 9. Something older _might_ build
binaries (such as integration test binaries), but may silently drop required
compiler flags. Please ensure you're using the minimum required version of `gcc`.
Failure to do so might result in weird failures at runtime.

### CentOS 8 / Stream

    $ sudo dnf copr enable ngompa/musl-libc
    $ sudo dnf install git curl gcc-toolset-9 openssl-devel musl-gcc
    $ source "/opt/rh/gcc-toolset-9/enable"

Note: you may want to add that final `source` command to a `~/.profile`,
`~/.bashrc` / or `~/.bash_profile` equivalent, otherwise you must remember
to source that file prior to building `enarx-keepldr`.

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
