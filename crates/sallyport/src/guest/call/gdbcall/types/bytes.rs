// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::{Commit, Committer, Input};

#[repr(transparent)]
pub struct StagedBytesInput<'a>(pub Input<'a, [u8], &'a [u8]>);

impl<'a> Commit for StagedBytesInput<'a> {
    type Item = usize;

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        let len = self.0.len();
        self.0.commit(com);
        len
    }
}
