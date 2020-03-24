// SPDX-License-Identifier: Apache-2.0

use crt0stack::Reader;

fn main() {
    extern "C" {
        static environ: *const *const std::os::raw::c_char;
    }

    let reader = unsafe { Reader::from_environ(&*environ) }.prev().prev();
    assert_eq!(reader.count(), 1);

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
