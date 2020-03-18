// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
// TODO: https://github.com/enarx/enarx/issues/382
#![deny(missing_docs)]
#![allow(missing_docs)]

extern "C" {
    static environ: *const *const std::os::raw::c_char;
}

fn main() {
    let reader = unsafe { crt0stack::Reader::from_environ(&*environ) }
        .prev()
        .prev();

    let mut reader = reader.done();
    for arg in &mut reader {
        println!("arg: {:?}", arg);
    }

    let mut reader = reader.done();
    for env in &mut reader {
        println!("env: {:?}", env);
    }

    let mut reader = reader.done();
    for aux in &mut reader {
        println!("aux: {:?}", aux);
    }
}
