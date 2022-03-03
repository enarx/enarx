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
    }
}

pub fn kvm_version() -> Datum {
    let version = Kvm::new().map(|kvm| kvm.get_api_version());
    let (pass, info) = match version {
        Ok(v) => (v == 12, Some(v.to_string())),
        Err(_) => (false, None),
    };

    Datum {
        name: " API Version".into(),
        pass,
        info,
        mesg: None,
    }
}

pub const CPUIDS: &[CpuId] = &[CpuId {
    name: "CPU",
    leaf: 0x80000000,
    subl: 0x00000000,
    func: |res| CpuId::cpu_identifier(res, None),
    vend: None,
}];
