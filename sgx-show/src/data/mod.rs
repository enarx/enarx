// SPDX-License-Identifier: Apache-2.0

pub mod cpuid;

pub trait Data: std::fmt::Display {
    type Type;

    fn data(&self) -> Option<Self::Type>;
}
