use core::mem::size_of;

#[derive(Copy)]
#[repr(transparent)]
pub struct Padding<T>(T);

impl<T> Clone for Padding<T> {
    fn clone(&self) -> Self {
        Default::default()
    }
}

impl<T> Default for Padding<T> {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl<T> core::fmt::Display for Padding<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Padding({})", size_of::<Self>())
    }
}

impl<T> core::fmt::Debug for Padding<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Padding({})", size_of::<Self>())
    }
}

impl<T> Eq for Padding<T> {}
impl<T> PartialEq for Padding<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

#[test]
#[cfg(test)]
fn padding() {
    assert_eq!(size_of::<Padding<[u8; 20]>>(), 20);
}
