// SPDX-License-Identifier: Apache-2.0

use super::*;
use core::ops::*;

/// Expresses a linear set by its starting and termination points
///
/// This type is fully isomorphic with `core::ops::Range` and `Span`. However,
/// unlike `core::ops::Range`, this type is not an iterator and therefore can
/// implement `Copy`. Points may have any number of dimensions.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Line<T> {
    /// The start point
    pub start: T,

    /// The first point excluded by the set
    pub end: T,
}

impl<T> From<Range<T>> for Line<T> {
    #[inline(always)]
    fn from(value: Range<T>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl<T> From<Line<T>> for Range<T> {
    #[inline(always)]
    fn from(value: Line<T>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl<T: PartialOrd> Contains<T> for Line<T> {
    #[inline(always)]
    fn contains(&self, value: &T) -> bool {
        if self.start < self.end {
            &self.start <= value && value < &self.end
        } else {
            &self.start >= value && value > &self.end
        }
    }
}

impl<T: PartialOrd> Contains<Self> for Line<T> {
    #[inline(always)]
    fn contains(&self, value: &Self) -> bool {
        self.contains(&value.start) && self.contains(&value.end)
    }
}

impl<T: PartialEq> Empty for Line<T> {
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

impl<T: PartialOrd> Split<Self> for Line<T> {
    #[inline(always)]
    fn split(self, at: Self) -> Option<(Self, Self)> {
        if !self.contains(&at.start) && at.start != self.end {
            return None;
        }

        if !self.contains(&at.end) && at.end != self.end {
            return None;
        }

        let l = Self {
            start: self.start,
            end: at.start,
        };

        let r = Self {
            start: at.end,
            end: self.end,
        };

        Some((l, r))
    }
}

impl<T: PartialOrd + Copy> Split<T> for Line<T> {
    #[inline(always)]
    fn split(self, at: T) -> Option<(Self, Self)> {
        self.split(Self { start: at, end: at })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! x {
        ($range:expr) => {
            Line::from($range)
        };
    }

    #[test]
    fn convert() {
        let range = 2..3;
        let line = Line { start: 2, end: 3 };

        assert_eq!(range, line.into());
        assert_eq!(line, range.into());
    }

    #[test]
    fn contains() {
        assert!(!x!(2..3).contains(&1));
        assert!(x!(2..3).contains(&2));
        assert!(!x!(2..3).contains(&3));

        assert!(!x!(3..2).contains(&1));
        assert!(!x!(3..2).contains(&2));
        assert!(x!(3..2).contains(&3));

        assert!(x!(0..9).contains(&x!(2..4)));
        assert!(x!(0..9).contains(&x!(0..0)));
        assert!(x!(0..9).contains(&x!(5..5)));
        assert!(!x!(0..9).contains(&x!(9..9)));
        assert!(!x!(0..9).contains(&x!(2..14)));
        assert!(!x!(0..9).contains(&x!(12..14)));

        assert!(x!(8..3).contains(&x!(5..7)));
        assert!(!x!(8..3).contains(&x!(5..17)));
        assert!(!x!(8..3).contains(&x!(15..17)));
    }

    #[test]
    fn is_empty() {
        assert!(x!(2..2).is_empty());
        assert!(!x!(2..3).is_empty());
    }

    #[test]
    fn split() {
        assert_eq!(x!(2..4).split(1), None);
        assert_eq!(x!(2..4).split(2), Some((x!(2..2), x!(2..4))));
        assert_eq!(x!(2..4).split(3), Some((x!(2..3), x!(3..4))));
        assert_eq!(x!(2..4).split(4), Some((x!(2..4), x!(4..4))));
        assert_eq!(x!(2..4).split(5), None);

        assert_eq!(x!(2..5).split(x!(1..4)), None);
        assert_eq!(x!(2..5).split(x!(3..6)), None);
        assert_eq!(x!(2..5).split(x!(2..2)), Some((x!(2..2), x!(2..5))));
        assert_eq!(x!(2..5).split(x!(2..3)), Some((x!(2..2), x!(3..5))));
        assert_eq!(x!(2..5).split(x!(3..3)), Some((x!(2..3), x!(3..5))));
        assert_eq!(x!(2..5).split(x!(3..4)), Some((x!(2..3), x!(4..5))));
        assert_eq!(x!(2..5).split(x!(4..5)), Some((x!(2..4), x!(5..5))));
        assert_eq!(x!(2..5).split(x!(5..5)), Some((x!(2..5), x!(5..5))));
    }
}
