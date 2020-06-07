## Intel SGX 2 Static Binary Demo

This demo is designed to illustrate a static binary running in a SGX Enclave.
This demo *does not yet* include attestation.

### Hardware Requirements
SGX2 support is required to run this demo. Check with your hardware manufacturer
to determine if your hardware has SGX2 support enabled. Alternatively, you may
reference the following page for an incomplete but growing list of SGX enabled
hardware: https://github.com/ayeks/SGX-hardware/#hardware-with-sgx2-support

### Software Requirements
Operating System: [Fedora 32](https://getfedora.org/en/workstation/download/)

*Patched Fedora 32 kernels are required for this demo.*
Download patched kernels for Fedora 32 at
https://copr.fedorainfracloud.org/coprs/npmccallum/enarx/.
To use the patched kernels for Fedora 32,
`sudo dnf copr enable npmccallum/enarx && sudo dnf update`, then reboot.

At this point, you should be able to see `/dev/sgx/enclave`.

#### Rust

Ensure you have Rust installed according to the detailed guidance found at
https://github.com/enarx/enarx/wiki/How-to-contribute-code#rust.

Once you have completed the installation instructions, run the following commands:
```shell
$ cargo make build
$ enarx-keep-sgx/target/debug/enarx-keep-sgx \
  --code payload/target/x86_64-unknown-linux-musl/debug/payload \
  --shim enarx-keep-sgx-shim/target/x86_64-unknown-linux-musl/debug/enarx-keep-sgx-shim
```
