// SPDX-License-Identifier: Apache-2.0

/// A single page of memory
///
/// This type is page-aligned and page-sized.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(C, align(4096))]
pub struct Page([[u64; 32]; 16]);

impl Default for Page {
    fn default() -> Self {
        Self([[0; 32]; 16])
    }
}

impl AsRef<[u8]> for Page {
    fn as_ref(&self) -> &[u8] {
        unsafe { self.0.align_to().1 }
    }
}

impl AsMut<[u8]> for Page {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { self.0.align_to_mut().1 }
    }
}

impl Page {
    /// Returns the size of the page in bytes
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Copy a value into the start of a page
    ///
    /// All unused bytes are zero.
    ///
    /// The following constraints MUST apply to the value:
    ///   1. `align_of_val(&value) <= align_of::<Page>()`
    ///   2. `size_of_val(&value) <= size_of::<Page>()`
    pub fn copy<T: Copy>(value: T) -> Page {
        let mut pages = [Page::default()];
        let bytes = unsafe { pages.align_to_mut::<u8>().1 };
        let typed = unsafe { bytes.align_to_mut().1 };
        typed[0] = value;
        pages[0]
    }
}
