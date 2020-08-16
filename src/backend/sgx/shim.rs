// SPDX-License-Identifier: Apache-2.0

use bounds::{Contains as _, Span};

const PREFIX: usize = units::bytes![4; MiB];
const ALIGN: usize = units::bytes![2; MiB];
const STACK: usize = units::bytes![8; MiB];
const HEAP: usize = units::bytes![128; MiB];
const SIZE: usize = units::bytes![64; GiB];

const fn lower(value: usize, boundary: usize) -> usize {
    value / boundary * boundary
}

const fn raise(value: usize, boundary: usize) -> usize {
    lower(value + boundary - 1, boundary)
}

fn above(rel: impl Into<Line<usize>>, size: usize) -> Span<usize> {
    Span {
        start: raise(rel.into().end, ALIGN),
        count: size,
    }
}

fn below(rel: impl Into<Line<usize>>, size: usize) -> Span<usize> {
    Span {
        start: lower(rel.into().start - size, ALIGN),
        count: size,
    }
}

include!("../../../shims/shim-sgx/src/hostlib.rs");

impl Layout {
    /// Calculate the memory layout of the SGX keep
    pub fn calculate(shim: Line<usize>, code: Line<usize>) -> Self {
        assert_eq!(shim.start, 0);

        let shim: Line<usize> = above(
            Span {
                start: units::bytes!(32; TiB) + units::bytes!(63;GiB),
                count: 0,
            },
            Span::from(shim).count,
        )
        .into();

        let enclave = Line::from(Span {
            start: lower(shim.end, SIZE),
            count: SIZE,
        });

        assert!(enclave.contains(&shim.start));
        assert!(enclave.contains(&shim.end));
        assert_eq!(code.start, 0);

        let prefix = Span {
            start: enclave.start,
            count: PREFIX,
        }
        .into();
        let code = above(prefix, Span::from(code).count);
        let heap = above(code, HEAP);
        let stack = below(shim, STACK);

        Self {
            enclave,

            prefix,
            code: code.into(),
            heap: heap.into(),
            stack: stack.into(),
            shim,
        }
    }
}
