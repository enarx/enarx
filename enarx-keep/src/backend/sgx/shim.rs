// SPDX-License-Identifier: Apache-2.0

use lset::{Contains as _, Span};
use nbytes::bytes;

const PREFIX: usize = bytes![4; MiB];
const ALIGN: usize = bytes![2; MiB];
const STACK: usize = bytes![8; MiB];
const HEAP: usize = bytes![128; MiB];
const SIZE: usize = bytes![64; GiB];

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

include!("../../../internal/shim-sgx/src/hostlib.rs");

impl Layout {
    /// Calculate the memory layout of the SGX keep
    pub fn calculate(shim: Line<usize>, code: Line<usize>) -> Self {
        assert_eq!(shim.start, 0);

        let shim: Line<usize> = above(
            Span {
                start: bytes!(32; TiB) + bytes!(63;GiB),
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
