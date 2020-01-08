use core::arch::x86_64::__cpuid_count;
use core::marker::PhantomData;

macro_rules! mkcpuid {
    ($($name:ident: $leaf:expr, $subl:expr;)+) => {
        $(
            pub struct $name;

            impl Leaf for $name {
                const LEAF: u32 = $leaf;
                const SUBL: u32 = $subl;
            }

            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "CPUID[0x{:02X}, 0x{:02X}]", Self::LEAF, Self::SUBL)
                }
            }
        )+
    };
}

mkcpuid! {
    CpuInfo: 0x00000000, 0x00000000;
    ExtFeat: 0x00000007, 0x00000000;
    SgxCaps: 0x00000012, 0x00000000;
    SgxAttr: 0x00000012, 0x00000001;
}

pub trait Leaf: std::fmt::Display {
    const LEAF: u32;
    const SUBL: u32;
}

pub struct CpuId<T: Leaf>(pub u128, PhantomData<T>);

impl<T: Leaf> CpuId<T> {
    pub fn eax(&self) -> u32 {
        (self.0 >> 3 * 32) as u32
    }

    pub fn ebx(&self) -> u32 {
        (self.0 >> 2 * 32) as u32
    }

    pub fn ecx(&self) -> u32 {
        (self.0 >> 1 * 32) as u32
    }

    pub fn edx(&self) -> u32 {
        (self.0 >> 0 * 32) as u32
    }
}

impl<T: Leaf> From<CpuId<T>> for u128 {
    fn from(value: CpuId<T>) -> Self {
        value.0
    }
}

impl<T: Leaf> super::Data for T {
    type Type = CpuId<T>;

    fn data(&self) -> Option<Self::Type> {
        let res = unsafe { __cpuid_count(Self::LEAF, Self::SUBL) };

        let mut out = res.eax as u128;

        out <<= 32;
        out |= res.ebx as u128;

        out <<= 32;
        out |= res.ecx as u128;

        out <<= 32;
        out |= res.edx as u128;

        Some(CpuId(out, PhantomData))
    }
}
