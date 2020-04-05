// SPDX-License-Identifier: Apache-2.0

use super::component::Component;

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

    pub entry: usize,
}

impl Layout {
    pub fn calculate(shim: &Component, code: &Component) -> Self {
        let entry = code.entry;
        let code = code.region();
        let shim = shim.region();

        let enclave = Line::from(Span {
            start: lower(shim.end, SIZE),
            count: SIZE,
        });

        assert!(enclave.contains(&shim.start));
        assert!(enclave.contains(&shim.end));
        assert!(enclave.contains(&code.start));
        assert!(enclave.contains(&code.end));
        assert!(enclave.start + PREFIX <= code.start);

        let prefix = enclave.start..code.start;
        let heap = above(code, HEAP);
        let stack = below(shim, STACK);

        Self {
            enclave,

            prefix: prefix.into(),
            code,
            heap: heap.into(),
            stack: stack.into(),
            shim,

            entry,
        }
    }
}
