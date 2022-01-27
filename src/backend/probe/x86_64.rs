// SPDX-License-Identifier: Apache-2.0

use crate::backend::Datum;

use static_assertions::const_assert_eq;

use std::arch::x86_64::{CpuidResult, __cpuid, __cpuid_count};
use std::convert::From;
use std::io::{Error, ErrorKind, Result};
use std::mem::size_of;
use std::str::from_utf8;

const AUTHENTIC_AMD: &str = "AuthenticAMD";
const GENUINE_INTEL: &str = "GenuineIntel";

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Vendor {
    Amd,
    Intel,
}

impl Vendor {
    pub fn get() -> Result<Self> {
        let res = unsafe { __cpuid_count(0x00000000, 0x00000000) };
        let name = [
            res.ebx.to_le_bytes(),
            res.edx.to_le_bytes(),
            res.ecx.to_le_bytes(),
        ]
        .concat();

        let name = from_utf8(&name[..]).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("vendor string parse error: {:#?}", e),
            )
        })?;

        match name {
            AUTHENTIC_AMD => Ok(Self::Amd),
            GENUINE_INTEL => Ok(Self::Intel),
            name => Err(Error::new(
                ErrorKind::Other,
                format!("unsupported vendor: '{}'", name),
            )),
        }
    }

    pub const fn id(&self) -> &str {
        match self {
            Vendor::Amd => AUTHENTIC_AMD,
            Vendor::Intel => GENUINE_INTEL,
        }
    }
}

pub struct CpuId {
    pub name: &'static str,
    pub leaf: u32,
    pub subl: u32,
    pub func: fn(CpuidResult) -> (bool, Option<String>),
    pub vend: Option<Vendor>,
}

impl CpuId {
    /// Get the Processor Brand String or the CPU manufacturer if unavailable.
    pub fn cpu_identifier(
        res: CpuidResult,
        required_vendor: Option<Vendor>,
    ) -> (bool, Option<String>) {
        let vendor = Vendor::get();
        let supported_cpu =
            required_vendor.is_none() || required_vendor.as_ref() == vendor.as_ref().ok();
        let identifier_fmt = |name: Option<&str>| {
            format!(
                "{} | {}",
                name.unwrap_or("[unknown model]"),
                vendor
                    .map(|v| v.id().to_string())
                    .unwrap_or_else(|e| format!("[{}]", e))
            )
        };

        if res.eax < 0x80000004 {
            // The processor brand string (model) is unavailable.
            return (supported_cpu, Some(identifier_fmt(None)));
        }

        // https://en.wikipedia.org/wiki/CPUID#EAX=80000002h,80000003h,80000004h:_Processor_Brand_String
        const LEAVES: [u32; 3] = [0x80000002, 0x80000003, 0x80000004];
        const CHUNK_SIZE: usize = size_of::<u32>() * 4;
        const MODEL_LEN: usize = LEAVES.len() * CHUNK_SIZE;
        const_assert_eq!(MODEL_LEN, 48);
        let mut model: [u8; MODEL_LEN] = [0; MODEL_LEN];

        // Copy the string in 3 parts over several calls.
        for (i, leaf) in LEAVES.into_iter().enumerate() {
            // Get the next part of the model name.
            let res = unsafe { __cpuid(leaf) };
            let string_part = [
                res.eax.to_le_bytes(),
                res.ebx.to_le_bytes(),
                res.ecx.to_le_bytes(),
                res.edx.to_le_bytes(),
            ]
            .concat();
            // Copy all 4 registers into the model name.
            let start = i * CHUNK_SIZE;
            let destination = &mut model[start..start + CHUNK_SIZE];
            destination.clone_from_slice(&string_part);
        }

        let model_name = String::from_utf8_lossy(model.as_slice());
        (
            supported_cpu,
            Some(identifier_fmt(Some(model_name.trim_matches(char::from(0))))),
        )
    }
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
