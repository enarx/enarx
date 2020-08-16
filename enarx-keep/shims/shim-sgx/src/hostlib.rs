// SPDX-License-Identifier: Apache-2.0

// The common Layout for `enarx-keep-sgx` and `enarx-keep-sgx-shim`

use bounds::Line;

/// The enclave layout
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The boundaries of the enclave.
    pub enclave: Line<usize>,

    /// The boundaries of the prefix.
    pub prefix: Line<usize>,

    /// The boundaries of the code.
    pub code: Line<usize>,

    /// The boundaries of the heap.
    pub heap: Line<usize>,

    /// The boundaries of the stack.
    pub stack: Line<usize>,

    /// The boundaries of the shim.
    pub shim: Line<usize>,
}
