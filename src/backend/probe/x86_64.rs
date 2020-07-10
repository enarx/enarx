// SPDX-License-Identifier: Apache-2.0

use crate::backend::Datum;

use std::arch::x86_64::{CpuidResult, __cpuid_count};
use std::convert::From;

pub struct CpuId {
    pub name: &'static str,
    pub leaf: u32,
    pub subl: u32,
    pub func: fn(CpuidResult) -> (bool, Option<String>),
}

impl From<&CpuId> for Datum {
    fn from(cpuid: &CpuId) -> Datum {
        let max = unsafe { __cpuid_count(0x00000000, 0x00000000) }.eax;

        let (pass, info) = if cpuid.leaf <= max {
            (cpuid.func)(unsafe { __cpuid_count(cpuid.leaf, cpuid.subl) })
        } else {
            (false, None)
        };

        Datum {
            name: cpuid.name.into(),
            mesg: None,
            pass,
            info,
        }
    }
}
