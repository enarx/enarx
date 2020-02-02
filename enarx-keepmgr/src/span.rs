use std::ops::{Add, Range, Sub};

/// A span
#[derive(Copy, Clone, Debug)]
pub struct Span<T> {
    /// The beginning of the span
    pub start: T,

    /// The number of elments in the span
    pub count: T,
}

impl<T: Clone + Sub<T, Output = T>> From<Range<T>> for Span<T> {
    fn from(value: Range<T>) -> Self {
        Span {
            start: value.start.clone(),
            count: value.end - value.start,
        }
    }
}

impl<T: Clone + Add<T, Output = T>> From<Span<T>> for Range<T> {
    fn from(value: Span<T>) -> Self {
        Range {
            start: value.start.clone(),
            end: value.start + value.count,
        }
    }
}
