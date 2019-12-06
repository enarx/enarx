//! Welcome to `paged`, a wrapper struct for page alignement and padding!
//!
//! When interacting with kernels, it is often required that the references
//! passed be page-aligned and page-sized. However, specifying this
//! alignment on the type itself imposes runtime overhead when using these
//! types in userspace. This can be particularly painful for small types.
//!
//! The `paged` crate solves this problem with a convenient wrapper type.
//! For example:
//!
//! ```
//! use core::mem::*;
//! use paged::*;
//!
//! struct Foo(u32, u32);
//!
//! // The size and allocation of Foo are normal.
//! assert_eq!(size_of::<Foo>(), 8);
//! assert_eq!(align_of::<Foo>(), align_of::<u32>());
//!
//! // The size and allocation of Page<Size4k, Foo> are paged.
//! assert_eq!(size_of::<Page<Size4k, Foo>>(), 4096);
//! assert_eq!(align_of::<Page<Size4k, Foo>>(), 4096);
//!
//! struct Bar(u32, [u8; 4096]);
//!
//! // The size and allocation of Bar are normal.
//! assert_eq!(size_of::<Bar>(), size_of::<(u32, [u8; 4096])>());
//! assert_eq!(align_of::<Bar>(), align_of::<u32>());
//!
//! // The size and allocation of Page<Size4k, Bar> are paged.
//! // NOTE: the size spills over onto the next page.
//! assert_eq!(size_of::<Page<Size4k, Bar>>(), 8192);
//! assert_eq!(align_of::<Page<Size4k, Bar>>(), 4096);
//! ```
//!
//! By using `Page`, you can avoid polluting your core types with alignment
//! and padding. This means that you get the alignment and padding when
//! you need it, but you don't pay the overhead when you don't.
//!
//! Zero-cost abstractions FTW!

#[warn(clippy::all)]

/// A marker trait identifying the size of a page
///
/// Pages can have different sizes. You might need to pick between them
/// at run-time. This abstraction allows you to select your page size as
/// appropriate.
pub trait PageSize: Copy + Clone + Default {
    const BYTES: usize;
}

macro_rules! mksize {
    ($name:ident, $size:expr) => {
        #[repr(align($size))]
        #[derive(Copy, Clone, Default)]
        pub struct $name;
        impl PageSize for $name {
            const BYTES: usize = $size;
        }
    };
}

mksize!(Size4k, 4096);
mksize!(Size16k, 16384);
mksize!(Size64k, 65536);

/// A wrapper that places a type in a page
///
/// The `Page` struct ensures that the embedded type is aligned to a
/// page boundary and is sized to a multiple of the page size. You don't
/// have to pay for the alignment and padding overhead until you need it!
#[repr(C)]
pub struct Page<S: PageSize, T: Sized>(S, T, S);

impl<S: PageSize, T> AsRef<T> for Page<S, T> {
    fn as_ref(&self) -> &T {
        &self.1
    }
}

impl<S: PageSize, T> AsMut<T> for Page<S, T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.1
    }
}

impl<S: PageSize, T> core::borrow::Borrow<T> for Page<S, T> {
    fn borrow(&self) -> &T {
        &self.1
    }
}

impl<S: PageSize, T> core::borrow::BorrowMut<T> for Page<S, T> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.1
    }
}

impl<S: PageSize, T: Clone> Clone for Page<S, T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1.clone(), self.2)
    }
}

impl<S: PageSize, T: Copy> Copy for Page<S, T> {}

impl<S: PageSize, T: Default> Default for Page<S, T> {
    fn default() -> Self {
        Self(S::default(), Default::default(), S::default())
    }
}

impl<S: PageSize, T: Eq> Eq for Page<S, T> {}

impl<S: PageSize, T: PartialEq> PartialEq for Page<S, T> {
    fn eq(&self, other: &Self) -> bool {
        self.1.eq(&other.1)
    }
}

impl<S: PageSize, T: Ord> Ord for Page<S, T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.1.cmp(&other.1)
    }
}

impl<S: PageSize, T: PartialOrd> PartialOrd for Page<S, T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.1.partial_cmp(&other.1)
    }
}

impl<S: PageSize, T: core::fmt::Debug> core::fmt::Debug for Page<S, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Page({:?})", self.1)
    }
}

impl<S: PageSize, T: core::fmt::Display> core::fmt::Display for Page<S, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Page({})", self.1)
    }
}

impl<S: PageSize, T> From<T> for Page<S, T> {
    fn from(value: T) -> Self {
        Self(S::default(), value, S::default())
    }
}

impl<S: PageSize, T: core::hash::Hash> core::hash::Hash for Page<S, T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.1.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::*;

    #[test]
    fn align4k() {
        assert_eq!(align_of::<Page<Size4k, [u8; 0]>>(), Size4k::BYTES);
        assert_eq!(align_of::<Page<Size4k, [u8; 1]>>(), Size4k::BYTES);
        assert_eq!(
            align_of::<Page<Size4k, [u8; Size4k::BYTES - 1]>>(),
            Size4k::BYTES
        );
        assert_eq!(
            align_of::<Page<Size4k, [u8; Size4k::BYTES + 0]>>(),
            Size4k::BYTES
        );
        assert_eq!(
            align_of::<Page<Size4k, [u8; Size4k::BYTES + 1]>>(),
            Size4k::BYTES
        );
    }

    #[test]
    fn align16k() {
        assert_eq!(align_of::<Page<Size16k, [u8; 0]>>(), Size16k::BYTES);
        assert_eq!(align_of::<Page<Size16k, [u8; 1]>>(), Size16k::BYTES);
        assert_eq!(
            align_of::<Page<Size16k, [u8; Size16k::BYTES - 1]>>(),
            Size16k::BYTES
        );
        assert_eq!(
            align_of::<Page<Size16k, [u8; Size16k::BYTES + 0]>>(),
            Size16k::BYTES
        );
        assert_eq!(
            align_of::<Page<Size16k, [u8; Size16k::BYTES + 1]>>(),
            Size16k::BYTES
        );
    }

    #[test]
    fn align64k() {
        assert_eq!(align_of::<Page<Size64k, [u8; 0]>>(), Size64k::BYTES);
        assert_eq!(align_of::<Page<Size64k, [u8; 1]>>(), Size64k::BYTES);
        assert_eq!(
            align_of::<Page<Size64k, [u8; Size64k::BYTES - 1]>>(),
            Size64k::BYTES
        );
        assert_eq!(
            align_of::<Page<Size64k, [u8; Size64k::BYTES + 0]>>(),
            Size64k::BYTES
        );
        assert_eq!(
            align_of::<Page<Size64k, [u8; Size64k::BYTES + 1]>>(),
            Size64k::BYTES
        );
    }

    #[test]
    fn size4k() {
        assert_eq!(size_of::<Page<Size4k, [u8; 0]>>(), 0);
        assert_eq!(size_of::<Page<Size4k, [u8; 1]>>(), Size4k::BYTES);
        assert_eq!(
            size_of::<Page<Size4k, [u8; Size4k::BYTES - 1]>>(),
            Size4k::BYTES
        );
        assert_eq!(
            size_of::<Page<Size4k, [u8; Size4k::BYTES + 0]>>(),
            Size4k::BYTES
        );
        assert_eq!(
            size_of::<Page<Size4k, [u8; Size4k::BYTES + 1]>>(),
            Size4k::BYTES * 2
        );
    }

    #[test]
    fn size16k() {
        assert_eq!(size_of::<Page<Size16k, [u8; 0]>>(), 0);
        assert_eq!(size_of::<Page<Size16k, [u8; 1]>>(), Size16k::BYTES);
        assert_eq!(
            size_of::<Page<Size16k, [u8; Size16k::BYTES - 1]>>(),
            Size16k::BYTES
        );
        assert_eq!(
            size_of::<Page<Size16k, [u8; Size16k::BYTES + 0]>>(),
            Size16k::BYTES
        );
        assert_eq!(
            size_of::<Page<Size16k, [u8; Size16k::BYTES + 1]>>(),
            Size16k::BYTES * 2
        );
    }

    #[test]
    fn size64k() {
        assert_eq!(size_of::<Page<Size64k, [u8; 0]>>(), 0);
        assert_eq!(size_of::<Page<Size64k, [u8; 1]>>(), Size64k::BYTES);
        assert_eq!(
            size_of::<Page<Size64k, [u8; Size64k::BYTES - 1]>>(),
            Size64k::BYTES
        );
        assert_eq!(
            size_of::<Page<Size64k, [u8; Size64k::BYTES + 0]>>(),
            Size64k::BYTES
        );
        assert_eq!(
            size_of::<Page<Size64k, [u8; Size64k::BYTES + 1]>>(),
            Size64k::BYTES * 2
        );
    }
}
