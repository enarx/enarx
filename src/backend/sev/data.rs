// SPDX-License-Identifier: Apache-2.0

pub use crate::backend::kvm::data::{dev_kvm, kvm_version};

use crate::backend::probe::x86_64::{CpuId, Vendor};
use crate::backend::Datum;
use crate::caching::CrlList;

use crate::backend::sev::snp::vcek::{
    get_crl_reader_with_path, get_vcek_reader_with_path, sev_cache_dir,
};
use std::arch::x86_64::__cpuid_count;
use std::fs::OpenOptions;
use std::mem::MaybeUninit;
use std::time::SystemTime;

use der::Decode;

pub fn has_crl_cache() -> Result<Datum, Datum> {
    const NAME: &str = "AMD CRL cache file";
    const UPDATE_MSG: &str =
        "Run `enarx platform snp cache-crl` to generate the AMD CRL cache file.";

    let (path, mut reader) = get_crl_reader_with_path().map_err(|e| Datum {
        name: NAME.to_string(),
        pass: false,
        info: Some(e.to_string()),
        mesg: Some(UPDATE_MSG.to_string()),
        data: vec![],
    })?;

    let mut crls = Vec::new();
    std::io::copy(&mut reader, &mut crls).map_err(|e| Datum {
        name: NAME.to_string(),
        pass: false,
        info: Some(e.to_string()),
        mesg: Some(UPDATE_MSG.to_string()),
        data: vec![],
    })?;

    let crls = CrlList::from_der(&crls).map_err(|e| Datum {
        name: NAME.to_string(),
        pass: false,
        info: Some(e.to_string()),
        mesg: Some(UPDATE_MSG.to_string()),
        data: vec![],
    })?;

    for (_, crl) in crls.entries() {
        if let Some(update) = crl.tbs_cert_list.next_update {
            if update.to_system_time() <= SystemTime::now() {
                return Err(Datum {
                    name: NAME.to_string(),
                    pass: false,
                    info: None,
                    mesg: Some("CRLs expired! ".to_string() + UPDATE_MSG),
                    data: vec![],
                });
            }
        }
    }

    if let Some(next_update) = crls.next_update() {
        Ok(Datum {
            name: NAME.to_string(),
            pass: true,
            info: Some(format!(
                "{}, next update {}",
                path.to_string_lossy().into_owned(),
                next_update
            )),
            mesg: None,
            data: vec![],
        })
    } else {
        Ok(Datum {
            name: NAME.to_string(),
            pass: true,
            info: path.to_string_lossy().into_owned().into(),
            mesg: None,
            data: vec![],
        })
    }
}

pub fn has_vcek_cache() -> Datum {
    let name = "SEV-SNP VCEK key cache file".to_string();

    let cache_dir =
        match sev_cache_dir().and_then(|p| p.metadata().map(|_| p).map_err(anyhow::Error::from)) {
            Ok(cache_dir) => cache_dir,
            Err(e) => {
                return Datum {
                    name,
                    pass: false,
                    info: Some(e.to_string()),
                    mesg: Some(
                        "enarx expects the directory `/var/cache/amd-sev` to exist and be readable"
                            .to_string(),
                    ),
                    data: vec![],
                }
            }
        };

    match get_vcek_reader_with_path(cache_dir) {
        Ok((path, _)) => Datum {
            name,
            pass: true,
            info: path.to_string_lossy().into_owned().into(),
            mesg: None,
            data: vec![],
        },
        Err(e) => Datum {
            name,
            pass: false,
            info: Some(e.to_string()),
            mesg: Some(
                "Run `enarx platform snp vcek update` to generate the cache file.".to_string(),
            ),
            data: vec![],
        },
    }
}

pub fn has_reasonable_memlock_rlimit() -> Datum {
    let mut rlimits = MaybeUninit::uninit();
    let res = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, rlimits.as_mut_ptr()) };

    let (pass, info) = if res == 0 {
        let rlimit = unsafe { rlimits.assume_init() };

        /* footprint = approximately (size of shim + size of exec-wasmtime + size of workload) */
        let keep_footprint = nbytes::bytes![5; MiB];

        let num_keeps = rlimit.rlim_cur as usize / keep_footprint;
        let keep_status = format!(
            "{}{} keep{}",
            if num_keeps > 0 { "~" } else { "" },
            num_keeps,
            if num_keeps == 1 { "" } else { "s" }
        );

        let pass = num_keeps > 0;

        let info = format!(
            "{} (soft limit = {} bytes, hard limit = {} bytes)",
            keep_status, rlimit.rlim_cur, rlimit.rlim_max
        );

        (pass, Some(info))
    } else {
        (false, Some("failed to query memlock rlimit".into()))
    };

    let mesg = if !pass {
        let mesg = "The MEMLOCK rlimit must be large enough to \
                    accommodate the Enarx shim, exec-wasmtime, and the memory pressure \
                    requirements of the target workloads across all deployed SEV keeps.";
        Some(mesg.into())
    } else {
        None
    };

    Datum {
        name: "MEMLOCK rlimit allows for".into(),
        pass,
        info,
        mesg,
        data: vec![],
    }
}

pub fn dev_sev() -> Datum {
    Datum {
        name: "Driver".into(),
        pass: std::path::Path::new("/dev/sev").exists(),
        info: Some("/dev/sev".into()),
        mesg: None,
        data: vec![sev_enabled_in_kernel()],
    }
}

pub fn sev_enabled_in_kernel() -> Datum {
    let mut datum = Datum {
        name: "SEV-SNP is enabled in host kernel".into(),
        pass: false,
        info: None,
        mesg: None,
        data: vec![],
    };

    let mod_param = "/sys/module/kvm_amd/parameters/sev_snp";
    if std::path::Path::new(mod_param).exists() {
        if let Ok(val) = std::fs::read_to_string(mod_param) {
            datum.pass = val.trim() == "1" || val.trim() == "Y";
        }
    }

    datum
}

pub fn dev_sev_readable() -> Datum {
    let opts = OpenOptions::new().read(true).open("/dev/sev");

    Datum {
        name: "/dev/sev is readable by user".into(),
        pass: opts.is_ok(),
        info: None,
        mesg: None,
        data: vec![],
    }
}

pub fn dev_sev_writable() -> Datum {
    let opts = OpenOptions::new().write(true).open("/dev/sev");

    Datum {
        name: "/dev/sev is writable by user".into(),
        pass: opts.is_ok(),
        info: None,
        mesg: None,
        data: vec![],
    }
}

pub const CPUIDS: &[CpuId] = &[CpuId {
    name: "CPU",
    leaf: 0x80000000,
    subl: 0x00000000,
    func: |res| CpuId::cpu_identifier(res, Some(Vendor::Amd)),
    vend: None,
    data: &[
        CpuId {
            name: "Microcode support",
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
            data: &[],
        },
        CpuId {
            name: "Secure Memory Encryption (SME)",
            leaf: 0x8000001f,
            subl: 0x00000000,
            func: |res| (res.eax & 0x1 != 0, None),
            vend: Some(Vendor::Amd),
            data: &[
                CpuId {
                    name: "Physical address bit reduction",
                    leaf: 0x8000001f,
                    subl: 0x00000000,
                    func: |res| {
                        let field = res.ebx & 0b1111_1100_0000 >> 6;
                        (true, Some(format!("{field}")))
                    },
                    vend: Some(Vendor::Amd),
                    data: &[],
                },
                CpuId {
                    name: "C-bit location in page table entry",
                    leaf: 0x8000001f,
                    subl: 0x00000000,
                    func: |res| {
                        let field = res.ebx & 0b01_1111;
                        (true, Some(format!("{field}")))
                    },
                    vend: Some(Vendor::Amd),
                    data: &[],
                },
            ],
        },
        CpuId {
            name: "Secure Encrypted Virtualization (SEV)",
            leaf: 0x8000001f,
            subl: 0x00000000,
            func: |res| (res.eax & (1 << 1) != 0, None),
            vend: Some(Vendor::Amd),
            data: &[
                CpuId {
                    name: "Number of encrypted guests supported simultaneously",
                    leaf: 0x8000001f,
                    subl: 0x00000000,
                    func: |res| (true, Some(format!("{}", res.ecx))),
                    vend: Some(Vendor::Amd),
                    data: &[],
                },
                CpuId {
                    name: "Minimum ASID value for SEV-enabled, SEV-ES disabled guest",
                    leaf: 0x8000001f,
                    subl: 0x00000000,
                    func: |res| (true, Some(format!("{}", res.edx))),
                    vend: Some(Vendor::Amd),
                    data: &[],
                },
            ],
        },
        CpuId {
            name: "Secure Encrypted Virtualization Secure Nested Paging (SEV-SNP)",
            leaf: 0x8000001f,
            subl: 0x00000000,
            func: |res| (res.eax & (1 << 4) != 0, None),
            vend: Some(Vendor::Amd),
            data: &[],
        },
        CpuId {
            name: "Page Flush MSR available",
            leaf: 0x8000001f,
            subl: 0x00000000,
            func: |res| (res.eax & (1 << 2) != 0, None),
            vend: Some(Vendor::Amd),
            data: &[],
        },
    ],
}];
