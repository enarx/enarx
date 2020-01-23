// SPDX-License-Identifier: Apache-2.0

pub struct Debug<T: std::fmt::Debug>(std::marker::PhantomData<T>);

impl<T: std::fmt::Debug> Debug<T> {
    pub fn new() -> Self {
        Debug(std::marker::PhantomData)
    }
}

impl<T: std::fmt::Debug> super::Sink for Debug<T> {
    type Type = T;

    fn info(&self, value: &Self::Type) -> Option<String> {
        Some(format!("{:?}", value))
    }
}
