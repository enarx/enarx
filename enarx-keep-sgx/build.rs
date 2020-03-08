// SPDX-License-Identifier: Apache-2.0

fn main() {
    cc::Build::new().file("src/enclave.s").compile("enclave");
}
