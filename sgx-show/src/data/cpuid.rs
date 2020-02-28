// SPDX-License-Identifier: Apache-2.0

use core::arch::x86_64::{CpuidResult, __cpuid_count};
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

pub struct CpuId<T: Leaf>(CpuidResult, PhantomData<T>);

impl<T: Leaf> std::fmt::Debug for CpuId<T> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct("CpuId")
            .field("eax", &self.0.eax)
            .field("ebx", &self.0.ebx)
            .field("ecx", &self.0.ecx)
            .field("edx", &self.0.edx)
            .finish()
    }
}

impl<T: Leaf> CpuId<T> {
    pub fn eax(&self) -> u32 {
        self.0.eax
    }

    pub fn ebx(&self) -> u32 {
        self.0.ebx
    }

    pub fn ecx(&self) -> u32 {
        self.0.ecx
    }

    pub fn edx(&self) -> u32 {
        self.0.edx
    }
}

impl<T: Leaf> From<CpuId<T>> for u128 {
    fn from(value: CpuId<T>) -> Self {
        let mut out = 0;
        out |= value.0.eax as Self;

        out <<= 32;
        out |= value.0.ebx as Self;

        out <<= 32;
        out |= value.0.ecx as Self;

        out <<= 32;
        out |= value.0.edx as Self;

        out
    }
}

impl<T: Leaf> super::Data for T {
    type Type = CpuId<T>;

    fn data(&self) -> Option<Self::Type> {
        Some(CpuId(
            unsafe { __cpuid_count(Self::LEAF, Self::SUBL) },
            PhantomData,
        ))
    }
}
