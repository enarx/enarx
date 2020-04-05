// SPDX-License-Identifier: Apache-2.0

use span::{Contains as _, Line, Span};

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

// NOTE: this structure MUST be kept in sync with enarx-keep-sgx-shim
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Layout {
    pub enclave: Line<usize>,

    pub prefix: Line<usize>,
    pub code: Line<usize>,
    pub heap: Line<usize>,
    pub stack: Line<usize>,
    pub shim: Line<usize>,
}

impl Layout {
    pub fn calculate(shim: Line<usize>, code: Line<usize>) -> Self {
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
