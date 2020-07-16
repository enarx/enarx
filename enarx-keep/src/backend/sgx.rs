// SPDX-License-Identifier: Apache-2.0

use crate::backend;
use crate::backend::Datum;
use crate::binary::Component;

use sgx_types::attr::{Flags, Xfrm};
use sgx_types::misc::MiscSelect;

use std::arch::x86_64::{CpuidResult, __cpuid_count};
use std::fs::File;
use std::io::Result;
use std::mem::transmute;
use std::path::PathBuf;
use std::str::from_utf8;
use std::sync::Arc;

fn humanize(mut size: f64) -> (f64, &'static str) {
    let mut iter = 0;

    while size > 512.0 {
        size /= 1024.0;
        iter += 1;
    }

    let suffix = match iter {
        0 => "",
        1 => "KiB",
        2 => "MiB",
        3 => "GiB",
        4 => "TiB",
        5 => "PiB",
        6 => "EiB",
        7 => "ZiB",
        8 => "YiB",
        _ => panic!("Size unsupported!"),
    };

    (size, suffix)
}

struct CpuId {
    name: &'static str,
    leaf: u32,
    subl: u32,
    func: fn(CpuidResult) -> (bool, Option<String>),
}

const CPUIDS: &[CpuId] = &[
    CpuId {
        name: "CPU Manufacturer",
        leaf: 0x00000000,
        subl: 0x00000000,
        func: |res| {
            let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
            let name = from_utf8(&name[..]).unwrap();
            (name == "GenuineIntel", Some(name.into()))
        },
    },
    CpuId {
        name: " SGX Support",
        leaf: 0x00000007,
        subl: 0x00000000,
        func: |res| (res.ebx & (1 << 2) != 0, None),
    },
    CpuId {
        name: "  Version 1",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 0) != 0, None),
    },
    CpuId {
        name: "  Version 2",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 1) != 0, None),
    },
    CpuId {
        name: "  FLC Support",
        leaf: 0x00000007,
        subl: 0x00000000,
        func: |res| (res.ecx & (1 << 30) != 0, None),
    },
    CpuId {
        name: "  Max Size (32-bit)",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| {
            let bits = res.edx as u8;
            let (n, s) = humanize((1u64 << bits) as f64);
            (true, Some(format!("{:.0} {}", n, s)))
        },
    },
    CpuId {
        name: "  Max Size (64-bit)",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| {
            let bits = res.edx >> 8 & 0xff;
            let (n, s) = humanize((1u64 << bits) as f64);
            (true, Some(format!("{:.0} {}", n, s)))
        },
    },
    CpuId {
        name: "  MiscSelect",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| match MiscSelect::from_bits(res.ebx) {
            Some(ms) => (true, Some(format!("{:?}", ms))),
            None => (false, None),
        },
    },
    CpuId {
        name: "  Flags",
        leaf: 0x00000012,
        subl: 0x00000001,
        func: |res| match Flags::from_bits((res.ebx as u64) << 32 | res.eax as u64) {
            Some(flags) => (true, Some(format!("{:?}", flags))),
            None => (false, None),
        },
    },
    CpuId {
        name: "  Xfrm",
        leaf: 0x00000012,
        subl: 0x00000001,
        func: |res| match Xfrm::from_bits((res.edx as u64) << 32 | res.ecx as u64) {
            Some(flags) => (true, Some(format!("{:?}", flags))),
            None => (false, None),
        },
    },
];

fn epc_size(max: u32) -> Datum {
    let mut pass = false;
    let mut info = None;

    if max >= 0x00000012 {
        let mut size = 0;

        for i in 2.. {
            let result = unsafe { __cpuid_count(0x00000012, i) };
            if result.eax & 0xf != 1 {
                break;
            }

            let low = result.ecx as u64 & 0xfffff000;
            let high = result.edx as u64 & 0x000fffff;
            size += high << 12 | low;
        }

        let (n, s) = humanize(size as f64);
        info = Some(format!("{:.0} {}", n, s));
        pass = true;
    }

    Datum {
        name: "  EPC Size".into(),
        mesg: None,
        pass,
        info,
    }
}

fn dev_sgx_enclave() -> Datum {
    let mut pass = false;

    if File::open("/dev/sgx/enclave").is_ok() {
        pass = true;
    }

    Datum {
        name: "Driver".into(),
        pass,
        info: Some("/dev/sgx/enclave".into()),
        mesg: None,
    }
}

pub struct Backend;

impl backend::Backend for Backend {
    fn data(&self) -> Vec<Datum> {
        let mut data = vec![];

        data.push(dev_sgx_enclave());

        let max = unsafe { __cpuid_count(0x00000000, 0x00000000) }.eax;
        data.extend(CPUIDS.iter().map(|x| {
            let (pass, info) = if x.leaf <= max {
                (x.func)(unsafe { __cpuid_count(x.leaf, x.subl) })
            } else {
                (false, None)
            };

            Datum {
                name: x.name.into(),
                mesg: None,
                pass,
                info,
            }
        }));

        data.push(epc_size(max));

        data
    }

    fn shim(&self) -> Result<PathBuf> {
        unimplemented!()
    }

    /// Create a keep instance on this backend
    fn build(&self, shim: Component, code: Component) -> Result<Arc<dyn backend::Keep>> {
        unimplemented!()
    }
}
