// SPDX-License-Identifier: Apache-2.0

// This function is just for testing purposes and will be removed in the future
#[inline(always)]
pub fn hlt_loop() -> ! {
    loop {
        unsafe {
            _x86_64_asm_hlt();
        }
    }
}

extern "C" {
    // This function is just for testing purposes and will be removed in the future
    pub fn _enarx_asm_ud2();
    // This function is just for testing purposes and will be removed in the future
    pub fn _enarx_asm_io_hello_world();
    // This function is just for testing purposes and will be removed in the future
    pub fn _x86_64_asm_hlt();
}
