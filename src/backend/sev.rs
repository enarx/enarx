// SPDX-License-Identifier: Apache-2.0

use crate::backend::probe::x86_64::{CpuId, Vendor};
use crate::backend::{self, Datum, Keep};
use crate::binary::Component;

use std::arch::x86_64::__cpuid_count;
use std::fs::OpenOptions;
use std::io::Result;
use std::mem::transmute;
use std::path::PathBuf;
use std::str::from_utf8;
use std::sync::Arc;

const CPUIDS: &[CpuId] = &[
    CpuId {
        name: "CPU Manufacturer",
        leaf: 0x00000000,
        subl: 0x00000000,
        func: |res| {
            let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
            let name = from_utf8(&name[..]).unwrap();
            (name == "AuthenticAMD", Some(name.into()))
        },
        vend: None,
    },
    CpuId {
        name: " Microcode support",
        leaf: 0x80000002,
        subl: 0x00000000,
        func: |_res| {
            let cpu_name = {
                let mut bytestr = Vec::with_capacity(48);
                for cpuid in 0x8000_0002_u32..=0x8000_0004_u32 {
                    let cpuid = unsafe { __cpuid_count(cpuid, 0x0000_0000) };
                    let mut bytes: Vec<u8> = [cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx]
                        .iter()
                        .flat_map(|r| r.to_le_bytes().to_vec())
                        .collect();
                    bytestr.append(&mut bytes);
                }
                String::from_utf8(bytestr).unwrap().trim().to_string()
            };

            (cpu_name.to_uppercase().contains("EPYC"), Some(cpu_name))
        },
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: " Secure Memory Encryption (SME)",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| (res.eax & 0x1 != 0, None),
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: "  Physical address bit reduction",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| {
            let field = res.ebx & 0b1111_1100_0000 >> 6;
            (true, Some(format!("{}", field)))
        },
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: "  C-bit location in page table entry",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| {
            let field = res.ebx & 0b01_1111;
            (true, Some(format!("{}", field)))
        },
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: " Secure Encrypted Virtualization (SEV)",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 1) != 0, None),
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: "  Number of encrypted guests supported simultaneously",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| (true, Some(format!("{}", res.ecx))),
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: "  Minimum ASID value for SEV-enabled, SEV-ES disabled guest",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| (true, Some(format!("{}", res.edx))),
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: " Secure Encrypted Virtualization Encrypted State (SEV-ES)",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 3) != 0, None),
        vend: Some(Vendor::Amd),
    },
    CpuId {
        name: " Page Flush MSR available",
        leaf: 0x8000001f,
        subl: 0x00000000,
        func: |res| (res.eax & (1 << 2) != 0, None),
        vend: Some(Vendor::Amd),
    },
];

fn dev_sev() -> Datum {
    Datum {
        name: "Driver".into(),
        pass: std::path::Path::new("/dev/sev").exists(),
        info: Some("/dev/sev".into()),
        mesg: None,
    }
}

fn sev_enabled_in_kernel() -> Datum {
    let mut datum = Datum {
        name: " SEV is enabled in host kernel".into(),
        pass: false,
        info: None,
        mesg: None,
    };

    let mod_param = "/sys/module/kvm_amd/parameters/sev";
    if std::path::Path::new(mod_param).exists() {
        if let Ok(val) = std::fs::read_to_string(mod_param) {
            datum.pass = val.trim() == "1";
        }
    }

    datum
}

fn dev_sev_readable() -> Datum {
    let opts = OpenOptions::new().read(true).open("/dev/sev");

    Datum {
        name: " /dev/sev is readable by user".into(),
        pass: opts.is_ok(),
        info: None,
        mesg: None,
    }
}

fn dev_sev_writable() -> Datum {
    let opts = OpenOptions::new().write(true).open("/dev/sev");

    Datum {
        name: " /dev/sev is writable by user".into(),
        pass: opts.is_ok(),
        info: None,
        mesg: None,
    }
}

fn has_kvm_support() -> Datum {
    use crate::backend::Backend;
    Datum {
        name: "KVM support".into(),
        pass: backend::kvm::Backend.have(),
        info: None,
        mesg: None,
    }
}

pub struct Backend;

impl backend::Backend for Backend {
    fn data(&self) -> Vec<Datum> {
        let mut data = vec![];
        data.extend(CPUIDS.iter().map(|c| c.into()));
        data.push(dev_sev());
        data.push(sev_enabled_in_kernel());
        data.push(dev_sev_readable());
        data.push(dev_sev_writable());
        data.push(has_kvm_support());
        data
    }

    fn shim(&self) -> Result<PathBuf> {
        unimplemented!()
    }

    fn build(&self, shim: Component, code: Component) -> Result<Arc<dyn Keep>> {
        unimplemented!()
    }
}
