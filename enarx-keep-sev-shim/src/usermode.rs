// SPDX-License-Identifier: Apache-2.0

//! switch to Ring 3 aka usermode

extern "C" {
    /// Enter Ring 3
    ///
    /// # Safety
    ///
    /// Because the caller can give any `entry_point` and `stack_pointer`
    /// including 0, this function is unsafe.
    pub fn usermode(instruction_pointer: u64, stack_pointer: u64) -> !;
}
