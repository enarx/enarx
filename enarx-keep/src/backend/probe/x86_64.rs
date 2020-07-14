// SPDX-License-Identifier: Apache-2.0

use crate::backend::Datum;

use std::arch::x86_64::{CpuidResult, __cpuid_count};
use std::convert::From;
use std::io::{Error, ErrorKind, Result};
use std::mem::transmute;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Vendor {
    Amd,
    Intel,
}

impl Vendor {
    pub fn get() -> Result<Self> {
        let res = unsafe { __cpuid_count(0x00000000, 0x00000000) };
        let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
        let name = std::str::from_utf8(&name[..]).unwrap();

        Ok(match name {
            "AuthenticAMD" => Self::Amd,
            "GenuineIntel" => Self::Intel,
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unsupported vendor: {}", name),
                ))
            }
        })
    }
}

pub struct CpuId {
    pub name: &'static str,
    pub leaf: u32,
    pub subl: u32,
    pub func: fn(CpuidResult) -> (bool, Option<String>),
    pub vend: Option<Vendor>,
}

impl From<&CpuId> for Datum {
    fn from(cpuid: &CpuId) -> Datum {
        let datum = Datum {
            name: cpuid.name.into(),
            pass: false,
            info: None,
            mesg: None,
        };

        let this_vendor = match Vendor::get() {
            Ok(v) => v,
            Err(_) => return datum,
        };

        // If there is no vendor requirement for this CPUID
        // instruction, then the current vendor will suffice.
        let req_vendor = cpuid.vend.unwrap_or(this_vendor);

        // Many CPUID leaves aren't meaningful unless we know
        // for sure what kind of vendor we're running on.
        let (pass, info) = if this_vendor == req_vendor {
            (cpuid.func)(unsafe { __cpuid_count(cpuid.leaf, cpuid.subl) })
        } else {
            (false, None)
        };

        Datum {
            name: datum.name,
            pass,
            info,
            mesg: datum.mesg,
        }
    }
}
