use crate::data::cpuid::{CpuId, Leaf};

pub struct Bit<T: Leaf> {
    pub reg: fn(&CpuId<T>) -> u32,
    pub bit: u8,
}

impl<T: Leaf> super::Sink for Bit<T> {
    type Type = CpuId<T>;

    fn test(&self, data: &Self::Type) -> bool {
        (self.reg)(data) & (1 << self.bit) != 0
    }
}
