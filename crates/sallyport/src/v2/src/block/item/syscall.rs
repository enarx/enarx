// SPDX-License-Identifier: Apache-2.0

use libc::c_long;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Header {
    pub item: super::Header,
    pub num: c_long,
}
