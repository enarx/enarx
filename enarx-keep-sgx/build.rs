// SPDX-License-Identifier: Apache-2.0

fn main() {
    cc::Build::new().file("src/enter.s").compile("enter");
}
