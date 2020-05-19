// SPDX-License-Identifier: Apache-2.0

pub mod ioctl;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum State {
    Uninitialized,
    Initialized,
    Working,
}
