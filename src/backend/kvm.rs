// SPDX-License-Identifier: Apache-2.0

mod shim;
mod vm;

use crate::backend::{self, Datum, Keep};
use crate::binary::Component;

use anyhow::Result;
use kvm_ioctls::Kvm;

use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

const SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sev"));

fn dev_kvm() -> Datum {
    let dev_kvm = std::path::Path::new("/dev/kvm");

    Datum {
        name: "Driver".into(),
        pass: dev_kvm.exists(),
        info: Some("/dev/kvm".into()),
        mesg: None,
    }
}

fn kvm_version() -> Datum {
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

pub struct Backend;

impl backend::Backend for Backend {
    fn name(&self) -> &'static str {
        "kvm"
    }

    fn data(&self) -> Vec<Datum> {
        vec![dev_kvm(), kvm_version()]
    }

    fn build(&self, code: Component) -> Result<Arc<dyn Keep>> {
        let shim = Component::from_bytes(SHIM)?;

        let vm = vm::Builder::new()?
            .with_max_cpus(NonZeroUsize::new(256).unwrap())?
            .with_mem_size(units::bytes![1; GiB])?
            .calculate_layout(shim.region(), code.region())?
            .load_shim(shim)?
            .load_code(code)?
            .build()?;

        Ok(Arc::new(RwLock::new(vm)))
    }
}
