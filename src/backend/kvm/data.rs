// SPDX-License-Identifier: Apache-2.0

use crate::backend::{probe::x86_64::CpuId, Datum};
use kvm_ioctls::Kvm;

pub fn dev_kvm() -> Datum {
    let dev_kvm = std::path::Path::new("/dev/kvm");

    Datum {
        name: "Driver".into(),
        pass: dev_kvm.exists(),
        info: Some("/dev/kvm".into()),
        mesg: None,
        data: vec![kvm_version()],
    }
}

pub fn kvm_version() -> Datum {
    let version = Kvm::new().map(|kvm| kvm.get_api_version());
    let (pass, info) = match version {
        Ok(v) => (v == 12, Some(v.to_string())),
        Err(_) => (false, None),
    };

    Datum {
        name: "API Version".into(),
        pass,
        info,
        mesg: None,
        data: vec![],
    }
}

pub const CPUIDS: &[CpuId] = &[CpuId {
    name: "CPU",
    leaf: 0x80000000,
    subl: 0x00000000,
    func: |res| CpuId::cpu_identifier(res, None),
    vend: None,
    data: &[
        CpuId {
            name: "CPU supports FSGSBASE instructions",
            leaf: 0x00000007,
            subl: 0x00000000,
            func: |res| (res.ebx & 0x1 != 0, None),
            vend: None,
            data: &[],
        },
        CpuId {
            name: "CPU supports RDRAND instruction",
            leaf: 0x00000001,
            subl: 0x00000000,
            func: |res| (res.ecx & (1 << 30) != 0, None),
            vend: None,
            data: &[],
        },
    ],
}];
