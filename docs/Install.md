# Install Enarx from Source

This installation guide is for installing Enarx from source. For pre-compiled binaries, please reference the quickstart document available [here](Quickstart).

## Introduction

Enarx currently has support for Keeps running in Intel SGX and AMD SEV-SNP TEEs (Trusted Execution Environments). Please check the [Requirements](#requirements).  There is also support for application development using a "nil" backend which provides the same runtime, but no security isolation, and can run on a variety of Linux, Mac and Raspberry Pi systems.

In the [Initial Setup](#initial-setup) section, you'll find instructions on how to install dependencies for the various supported architectures and distributions. These dependencies include Rust and the toolchains.

Next, you'll find instructions on how to [install Enarx](#installing-enarx) from crates.io, GitHub, or Nix.

Finally, in the [Running Enarx](#running-enarx) section, you'll build and run your first `Hello World` WebAssembly module in Enarx.

## Requirements

### Recommended hardware

* Enarx requires specific hardware to run Keeps in a TEE instance, namely a CPU with a supported Trusted Execution Environment. Currently, Enarx Keeps are supported with ["Intel SGX"](#Setting-up-an-SGX-machine) and [AMD SEV-SNP](#Setting-up-an-SEV-SNP-machine).
* For development purposes, we provide the ["nil" backend](#Requirements-for-the-“nil”-backend), which does not require special hardware, or even a system running Linux.

### Setting up an SGX machine
Enarx requires SGX2 (SGX with EDMM) support.

For Intel, our recommendation would be the 3rd Gen Intel Xeon Scalable Ice Lake. This [article](https://www.servethehome.com/3rd-gen-intel-xeon-scalable-ice-lake-sku-list-and-value-analysis/) provides a comprehensive analysis of the different models. The 5318Y or 5318S provide good value.

- You must run a Linux kernel with patches applied from this repository tree: https://github.com/enarx/linux/tree/sgx
- Set the SGX device node permissions

```sh:sgx;
$ sudo groupadd -r sgx_prv
$ sudo bash -c "cat > /etc/udev/rules.d/99-sgx.rules" <<EOF
SUBSYSTEM=="misc", KERNEL=="sgx_provision", MODE="0660", GROUP="sgx_prv"
SUBSYSTEM=="misc", KERNEL=="sgx_enclave", MODE="0666"
EOF
```


### Setting up an SEV-SNP machine
#### Hardware requirements for SEV
For AMD our recommendation would be the EPYC 7003 Milan. This [article](https://www.servethehome.com/amd-epyc-7003-milan-sku-list-and-value-analysis/) offers an analysis of the different models.

- You must run a Linux kernel with patches applied from this repository tree: https://github.com/AMDESE/linux/tree/sev-snp-part2-v6
- Update the machine to the latest BIOS and/or install the [latest firmware](https://developer.amd.com/sev/):

```sh:snp;
$ wget -O amd_sev_fam19h_model0xh.sbin "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd/amd_sev_fam19h_model0xh.sbin?h=20220209"
$ sudo mv amd_sev_fam19h_model0xh.sbin /lib/firmware/amd/amd_sev_fam19h_model0xh.sbin
$ sudo chown root:root /lib/firmware/amd/amd_sev_fam19h_model0xh.sbin
```

- Set SEV device node permissions

```sh:snp;
$ sudo bash -c "echo 'KERNEL=="sev", MODE="0666"' > /etc/udev/rules.d/50-sev.rules"
```
- Increase the memlock limit for SEV keeps (need to pin a large number of pages)

```sh:snp;
$ sudo bash -c "echo '* - memlock 8388608' > /etc/security/limits.d/sev.conf"
```
- Enable SEV

```sh:snp;
$ sudo bash -c "echo 'options kvm_amd sev=1' > /etc/modprobe.d/kvm-amd.conf"
```



### Requirements for the "nil" backend

The `nil` backend does not require any special hardware, but any of the architectures supported by the `wasmtime` crate. These are currently:

* `aarch64-apple-darwin`
* `x86_64-apple-darwin`
* `aarch64-unknown-linux-gnu`
* `aarch64-unknown-linux-musl`
* `x86_64-unknown-linux-gnu`
* `x86_64-unknown-linux-musl`

This includes 64-bit Raspberry Pi and Apple M1.

### Requirements for KVM as a backend (alternative to "nil" backend)

KVM (Kernel-based Virtual Machine) is a full virtualization solution for Linux on x86 hardware containing virtualization extensions (Intel VT or AMD-V). It consists of a loadable kernel module, kvm.ko, that provides the core virtualization infrastructure and a processor specific module, kvm-intel.ko or kvm-amd.ko.

It's not always possible to have access to hardware with the support for Intel SGX or AMD SEV-SNP, hence, enarx supports KVM to facilitate the testing on more common hardware which have virtualization support. For the KVM support, the Intel VT and AMD-V features must be provided by the hardware.

KVM module is loaded by the Linux kernel automatically if the hardware supports the feature, hence, it's easy for anyone to set it up.

To check if the kvm module is loaded use the following command:
```sh:kvm;ID=debian ID=ubuntu
lsmod | grep kvm
```

If the module is loaded the following output should be expected
```console
kvm_intel    213   0
kvm 	      10   1 kvm_intel
```
or
```console
kvm_amd    23213   0
kvm 	      10   1 kvm_amd
```

## Initial Setup
Please choose one of the following:
* [Linux Install Dependencies](#linux-install-dependencies)
* [MacOS Install Dependencies](#macos-install-dependencies)

### Linux Install Dependencies

Please find instructions for your Linux distribution:

#### Fedora

```sh:ID=fedora
$ sudo dnf update -y
$ sudo dnf install -y git curl gcc musl-gcc
```

#### CentOS 8 / Stream
```sh:CPE_NAME="cpe:/o:centos:centos:8"
$ sudo dnf install -y dnf-plugins-core
$ sudo dnf copr -y enable ngompa/musl-libc
$ sudo dnf install -y git curl gcc-toolset-11 musl-gcc
$ source "/opt/rh/gcc-toolset-11/enable"
```
:::note

You may want to add that final `source` command to a `~/.profile`,
`~/.bashrc` / or `~/.bash_profile` equivalent, otherwise you must remember
to source that file prior to building `enarx`.

:::

#### CentOS 7 / Scientific Linux 7 and other clones
```sh:CPE_NAME="cpe:/o:centos:centos:7"
$ sudo yum install -y centos-release-scl-rh
```
or search for the package on https://centos.pkgs.org/ and install it manually with, for example:
```console
$ sudo yum install http://mirror.centos.org/centos/7/extras/x86_64/Packages/centos-release-scl-rh-2-3.el7.centos.noarch.rpm
```
and then:
```sh:CPE_NAME="cpe:/o:centos:centos:7"
$ sudo yum install -y yum-plugin-copr
$ sudo yum copr -y enable ngompa/musl-libc
$ sudo yum install -y git curl devtoolset-11 musl-gcc
$ source "/opt/rh/devtoolset-11/enable"
```

:::note

You may want to add that final `source` command to a `~/.profile`,
`~/.bashrc` / or `~/.bash_profile` equivalent, otherwise you must remember
to source that file prior to building `enarx`.

:::

#### Debian / Ubuntu
```sh:ID=debian ID=ubuntu
$ sudo apt update
$ sudo apt install -y git curl gcc musl-tools python3-minimal
```

:::tip

The minimum required `gcc` version is version 9. Something older _might_ build
binaries (such as integration test binaries), but may silently drop required
compiler flags. Please ensure you're using the minimum required version of `gcc`.
Failure to do so might result in weird failures at runtime.

:::

### MacOS Install Dependencies

#### Install Xcode
Compiling enarx on MacOS requires Xcode to be installed:
```console
xcode-select --install
sudo xcodebuild -license
```

### Install Rust

For installing Rust on Linux and MacOS please run the following:
```sh
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
$ source $HOME/.cargo/env
```

For installing Rust on Windows X86_64 please open a command prompt and run the following commands:
```console
C:\Users\User> curl.exe --output rustup-init.exe --url https://winget.rustup.rs/x86_64
C:\Users\User> rustup_init.exe --default-toolchain nightly -y
```

## Installing Enarx

You can install Enarx from GitHub, crates.io, or Nix.

### Install from GitHub
```sh:git;
$ git clone https://github.com/enarx/enarx
$ cd enarx/
$ cargo install --locked --bin enarx --path ./
```
### Install from crates.io

:::note

Rust version nightly-2022-06-28 is required when installing Enarx 0.5.1 from crates.io.

:::

For installing Enarx from crates.io on X86_64 Linux please run:
```sh:crates;
$ rustup toolchain install nightly-2022-06-28 -t x86_64-unknown-linux-musl,x86_64-unknown-linux-gnu,x86_64-unknown-none
$ CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS="-C linker=gcc" cargo +nightly-2022-06-28 -Z bindeps install --locked --bin enarx --version 0.5.1 -- enarx
```

For installing Enarx from crates.io on non-x86_64 Linux please run:
```console
$ rustup toolchain install nightly-2022-06-28
$ cargo +nightly-2022-06-28 -Z bindeps install --locked --bin enarx --version 0.5.1 -- enarx
```

### Install from Nix

Users with `nix` package manager installed (see https://nixos.org) should be able to just do in the checked out repository:
```sh:nix;
$ git clone https://github.com/enarx/enarx
$ cd enarx/
```
```sh:nix-legacy;
$ nix-shell
```
(on legacy, stable `nix` installs)

or:
```sh:nix-latest;
$ nix develop
```

:::note

`nix-shell` opens file descriptors `3` and `4` and the enarx `cargo test` fails therefore. `nix develop` does not seem to have this problem.

:::
## Running Enarx

### Build and run a WebAssembly module

Install the WebAssembly Rust toolchain:
```sh:helloworld;
$ rustup toolchain install nightly -t wasm32-wasi
```

Create a simple Rust program.  First make sure you're not in the repository you already created:
```sh:helloworld;
$ cd ~/
$ cargo init --bin hello-world
$ cd hello-world
$ echo 'fn main() { println!("Hello, Enarx!"); }' > src/main.rs
$ cargo +nightly build --release --target=wasm32-wasi
```

Assuming you did install the `enarx` binary and have it in your `$PATH`, you can
now run the WebAssembly program in an Enarx keep.
```sh:helloworld;
$ enarx run target/wasm32-wasi/release/hello-world.wasm
```
```console
[…]
Hello, Enarx!
```
If you want to suppress the debug output, add `2>/dev/null`.

### Select a Different Backend

`enarx` will probe the machine it is running on in an attempt to deduce an
appropriate deployment backend. To see what backends are supported on your
system, run:
```sh:git;
$ enarx platform info
```
You can manually select a backend with the `--backend` option, or by
setting the `ENARX_BACKEND` environment variable:

```sh:sgx-helloworld;
$ enarx run --backend=sgx target/wasm32-wasi/release/hello-world.wasm
$ ENARX_BACKEND=sgx enarx run target/wasm32-wasi/release/hello-world.wasm
```

##### Note about backends
`enarx` will look for backends in the following order, and use the first which it finds:
1. SGX or SEV-SNP
2. KVM
3. "nil" (a debug/developer backend without TEEs, isolation or any additional security guarentees)

The status of whether or not enarx was able to find the driver can be checked with the command `enarx platform info`. If the output shows any of the backends with a green "tick" or "checkmark", you are ready to use enarx with that backend.

When you execute the `enarx run` command, enarx tries to automatically select the appropriate backend. But if you want to specifically use the another supported backend you can pass the backend name ("sgx", "sev", "kvm" or "nil") as a parameter to `--backend` option, or set the `ENARX_BACKEND` environment variable with the name:

```sh:nil-helloworld;
$ enarx run --backend=nil target/wasm32-wasi/release/hello-world.wasm
$ ENARX_BACKEND=nil enarx run target/wasm32-wasi/release/hello-world.wasm
```

## Conclusion
Congratulations! You were able to run Enarx successfully!

Enarx was built to be simple to use. It abstracts away complex concepts and supports multiple architectures transparently so that users don't have to worry about these.

Enarx provides a WebAssembly runtime, offering developers a wide range of language choices for implementation, including Rust, C, C++, C#, Go, Java, Python and Haskell.

Enarx is CPU-architecture independent, enabling the same application code to be deployed across multiple targets, abstracting issues such as cross-compilation and differing attestation mechanisms between hardware vendors.

License: Apache-2.0
