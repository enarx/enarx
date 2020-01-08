pub struct Mask<T: core::ops::BitAnd<T, Output = T> + PartialEq + Copy> {
    pub mask: T,
    pub data: T,
}

impl<T: core::ops::BitAnd<T, Output = T> + PartialEq + Copy> super::Sink for Mask<T> {
    type Type = T;

    fn test(&self, data: &Self::Type) -> bool {
        self.data == *data & self.mask
    }
}
