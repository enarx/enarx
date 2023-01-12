// SPDX-License-Identifier: Apache-2.0

use crate::backend::probe::x86_64::{CpuId, Vendor};
use crate::backend::sgx::{sgx_cache_dir, AESM_SOCKET};
use crate::backend::Datum;
use crate::caching::CrlList;

use sgx::parameters::{Features, MiscSelect, Xfrm};

use std::arch::x86_64::__cpuid_count;
use std::fs::File;
use std::path::Path;
use std::time::SystemTime;

use der::Decode;

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

pub const CPUIDS: &[CpuId] = &[
    CpuId {
        name: "CPU",
        leaf: 0x80000000,
        subl: 0x00000000,
        func: |res| CpuId::cpu_identifier(res, Some(Vendor::Intel)),
        vend: None,
    },
    CpuId {
        name: " SGX Support",
        leaf: 0x00000007,
        subl: 0x00000000,
        func: |res| (res.ebx & (1 << 2) != 0, None),
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  Version 1",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 0) != 0, None),
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  Version 2",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 1) != 0, None),
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  FLC Support",
        leaf: 0x00000007,
        subl: 0x00000000,
        func: |res| (res.ecx & (1 << 30) != 0, None),
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  Max Size (32-bit)",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| {
            let bits = res.edx as u8;
            let (n, s) = humanize((1u64 << bits) as f64);
            (true, Some(format!("{n:.0} {s}")))
        },
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  Max Size (64-bit)",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| {
            let bits = res.edx >> 8 & 0xff;
            let (n, s) = humanize((1u64 << bits) as f64);
            (true, Some(format!("{n:.0} {s}")))
        },
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  MiscSelect",
        leaf: 0x00000012,
        subl: 0x00000000,
        func: |res| match MiscSelect::from_bits(res.ebx) {
            Some(ms) => (true, Some(format!("{ms:?}"))),
            None => (false, None),
        },
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  Features",
        leaf: 0x00000012,
        subl: 0x00000001,
        func: |res| match Features::from_bits((res.ebx as u64) << 32 | res.eax as u64) {
            Some(features) => (true, Some(format!("{features:?}"))),
            None => (false, None),
        },
        vend: Some(Vendor::Intel),
    },
    CpuId {
        name: "  Xfrm",
        leaf: 0x00000012,
        subl: 0x00000001,
        func: |res| match Xfrm::from_bits((res.edx as u64) << 32 | res.ecx as u64) {
            Some(flags) => (true, Some(format!("{flags:?}"))),
            None => (false, None),
        },
        vend: Some(Vendor::Intel),
    },
];

pub fn epc_size(max: u32) -> Datum {
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
        info = Some(format!("{n:.0} {s}"));
        pass = true;
    }

    Datum {
        name: "  EPC Size".into(),
        mesg: None,
        pass,
        info,
    }
}

pub fn dev_sgx_enclave() -> Datum {
    Datum {
        name: "Driver".into(),
        pass: File::open("/dev/sgx_enclave").is_ok(),
        info: Some("/dev/sgx_enclave".into()),
        mesg: None,
    }
}

pub fn aesm_socket() -> Datum {
    Datum {
        name: "AESM Daemon Socket".into(),
        pass: cfg!(feature = "disable-sgx-attestation") || Path::new(AESM_SOCKET).exists(),
        info: Some(AESM_SOCKET.into()),
        mesg: None,
    }
}

pub fn intel_crl() -> Datum {
    let name = "Intel CRL cache".to_string();
    let crl_file =
        match sgx_cache_dir() {
            Ok(p) => p.join("crls.der"),
            Err(e) => return Datum {
                name,
                pass: false,
                info: Some(e.to_string()),
                mesg: Some(
                    "enarx expects the directory `/var/cache/intel-sgx` to exist and be readable"
                        .into(),
                ),
            },
        };

    if !crl_file.exists() {
        return Datum {
            name,
            pass: false,
            info: None,
            mesg: Some(
                "Run `enarx platform sgx cache-crl` to generate the Intel CRL cache file".into(),
            ),
        };
    }

    let crls =
        match std::fs::read(crl_file.clone()) {
            Ok(c) => c,
            Err(e) => return Datum {
                name,
                pass: false,
                info: Some(e.to_string()),
                mesg: Some(
                    "Re-run `enarx platform sgx cache-crl` to generate the Intel CRL cache file"
                        .into(),
                ),
            },
        };

    let crls =
        match CrlList::from_der(&crls) {
            Ok(c) => c,
            Err(e) => return Datum {
                name,
                pass: false,
                info: Some(e.to_string()),
                mesg: Some(format!(
                    "Re-run `enarx platform sgx cache-crl` to generate the Intel CRL cache file `{crl_file:?}`")),
            },
        };

    for (_, crl) in crls.entries() {
        if let Some(update) = crl.tbs_cert_list.next_update {
            if update.to_system_time() <= SystemTime::now() {
                return Datum {
                    name,
                    pass: false,
                    info: None,
                    mesg: Some(
                        format!("CRLs expired, re-run `enarx platform sgx cache-crl` to update the Intel CRL cache file `{crl_file:?}`"),
                    ),
                };
            }
        }
    }

    Datum {
        name,
        pass: true,
        info: None,
        mesg: None,
    }
}
