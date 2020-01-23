// SPDX-License-Identifier: Apache-2.0

pub mod bit;
pub mod debug;
pub mod mask;

pub trait Sink {
    type Type;

    fn info(&self, _value: &Self::Type) -> Option<String> {
        None
    }

    fn test(&self, _data: &Self::Type) -> bool {
        true
    }
}
