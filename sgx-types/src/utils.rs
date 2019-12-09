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

#[test]
#[cfg(test)]
fn padding() {
    use core::mem::*;

    assert_eq!(size_of::<Padding<[u8; 20]>>(), 20);
}
