// SPDX-License-Identifier: Apache-2.0

use crt0stack::Reader;

fn main() {
    extern "C" {
        static environ: *const *const std::os::raw::c_char;
    }

    let reader = unsafe {
        let mut ptr = environ as *const usize;
        ptr = ptr.sub(1);
        assert_eq!(*ptr, 0);
        ptr = ptr.sub(1);

        let mut len = 0;
        while *ptr != len {
            ptr = ptr.sub(1);
            len += 1;
        }

        Reader::from_stack(&*(ptr as *const ()))
    };

    assert_eq!(reader.count(), 1);

    let mut reader = reader.done();
    for arg in &mut reader {
        eprintln!("arg: {:?}", arg);
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
