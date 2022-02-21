// SPDX-License-Identifier: Apache-2.0

//! Consuming, tail-recursive iterators.

/// An interface for dealing with consuming, tail-recursive iterators.
///
/// This is an adaptation of [`core::iter::Iterator`]. For more about the concept of iterators
/// generally, please see the [core::iter].
pub trait Iterator: Sized {
    type Item;

    /// Consumes the iterator and returns a tuple of the next value and iterator tail.
    ///
    /// Returns [`None`] when iteration is finished.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// use sallyport::iter::Iterator;
    ///
    /// let a = [1, 2, 3];
    ///
    /// let iter = a.iter();
    ///
    /// // A call to next() returns the next value...
    /// let (item, iter) = Iterator::next(iter).unwrap();
    /// assert_eq!(&1, item);
    /// let (item, iter) = iter.next().unwrap();
    /// assert_eq!(&2, item);
    /// let (item, iter) = iter.next().unwrap();
    /// assert_eq!(&3, item);
    ///
    /// // ... and then None once it's over.
    /// assert!(iter.next().is_none());
    /// ```
    fn next(self) -> Option<(Self::Item, Self)>;

    #[inline]
    fn fold<T, F>(self, init: T, mut f: F) -> T
    where
        F: FnMut(T, Self::Item) -> T,
    {
        let (mut accum, mut tail) = (init, self);
        while let Some((x, iter)) = tail.next() {
            accum = f(accum, x);
            tail = iter;
        }
        accum
    }

    #[inline]
    fn for_each<F>(self, f: F)
    where
        Self: Sized,
        F: FnMut(Self::Item),
    {
        #[inline]
        fn call<T>(mut f: impl FnMut(T)) -> impl FnMut((), T) {
            move |(), item| f(item)
        }

        self.fold((), call(f));
    }
}

impl<T: core::iter::Iterator> Iterator for T {
    type Item = T::Item;

    fn next(mut self) -> Option<(Self::Item, Self)> {
        T::next(&mut self).map(|item| (item, self))
    }
}

pub trait IntoIterator {
    type Item;
    type IntoIter: Iterator<Item = Self::Item>;

    fn into_iter(self) -> Self::IntoIter;
}

impl<T: core::iter::IntoIterator> IntoIterator for T {
    type Item = T::Item;
    type IntoIter = T::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        T::into_iter(self)
    }
}
