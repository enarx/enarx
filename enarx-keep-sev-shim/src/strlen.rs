// SPDX-License-Identifier: Apache-2.0

#[no_mangle]
pub extern "C" fn strlen(ptr: *const i8) -> usize {
    let mut i = ptr;
    loop {
        unsafe {
            if i.read() == 0 {
                return i.sub(ptr as _) as usize + 1;
            }
            i = i.add(1);
        }
    }
}
