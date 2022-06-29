// SPDX-License-Identifier: Apache-2.0

use crate::NULL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argv<const N: usize>(pub [usize; N]);

impl<const N: usize> From<Argv<N>> for [usize; N] {
    #[inline]
    fn from(argv: Argv<N>) -> Self {
        argv.0
    }
}

impl From<Argv<0>> for [usize; 4] {
    #[inline]
    fn from(_: Argv<0>) -> Self {
        [NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<0>> for [usize; 6] {
    #[inline]
    fn from(_: Argv<0>) -> Self {
        [NULL, NULL, NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<1>> for [usize; 4] {
    #[inline]
    fn from(argv: Argv<1>) -> Self {
        [argv.0[0], NULL, NULL, NULL]
    }
}

impl From<Argv<1>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<1>) -> Self {
        [argv.0[0], NULL, NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<2>> for [usize; 4] {
    #[inline]
    fn from(argv: Argv<2>) -> Self {
        [argv.0[0], argv.0[1], NULL, NULL]
    }
}

impl From<Argv<2>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<2>) -> Self {
        [argv.0[0], argv.0[1], NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<3>> for [usize; 4] {
    #[inline]
    fn from(argv: Argv<3>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], NULL]
    }
}

impl From<Argv<3>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<3>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], NULL, NULL, NULL]
    }
}

impl From<Argv<4>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<4>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], argv.0[3], NULL, NULL]
    }
}

impl From<Argv<5>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<5>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], argv.0[3], argv.0[4], NULL]
    }
}
