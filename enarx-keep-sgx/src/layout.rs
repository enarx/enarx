// SPDX-License-Identifier: Apache-2.0

use sgx_types::attr::Xfrm;
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
    pub xsavesize: usize,
}

impl Layout {
    pub fn calculate(shim: Line<usize>, code: Line<usize>, xfrm: sgx_types::attr::Xfrm) -> Self {
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

        // xsavesize is based on which flags are set in xfrm:
        // If the PKRU flag, AVX512 flags (HI16_ZMM, ZMM_Hi256, OPMASK),
        // MPX flags (BNDCSR, BNDREG), or AVX flag is set, the xsave
        // area will extend beyond the 576 bytes needed for the
        // xsavelegacy and xsaveheader regions (which are used if flags
        // X87 or SSE are set). We disregard CETU and CETS flags, as
        // these require CR4.CET = 1.
        let xsavesize = if xfrm.intersects(Xfrm::PKRU) {
            // xsavelegacy + xsaveheader + avx + mpx + avx512 + pkru
            512 + 64 + 256 + 256 + 1600 + 4
        } else if xfrm.intersects(Xfrm::HI16_ZMM)
            || xfrm.intersects(Xfrm::ZMM_HI256)
            || xfrm.intersects(Xfrm::OPMASK)
        {
            // xsavelegacy + xsaveheader + avx + mpx + avx512
            512 + 64 + 256 + 256 + 1600
        } else if xfrm.intersects(Xfrm::BNDCSR) || xfrm.intersects(Xfrm::BNDREG) {
            // xsavelegacy + xsaveheader + avx + mpx
            512 + 64 + 256 + 256
        } else if xfrm.intersects(Xfrm::AVX) {
            // xsavelegacy + xsaveheader + avx
            512 + 64 + 256
        } else {
            // xsavelegacy + xsaveheader
            512 + 64
        };

        Self {
            enclave,

            prefix,
            code: code.into(),
            heap: heap.into(),
            stack: stack.into(),
            shim,
            xsavesize,
        }
    }
}
