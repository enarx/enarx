// SPDX-License-Identifier: Apache-2.0

mod builder;
mod vm;

pub use vm::{
    measure::{self, Measurement},
    personality::Personality,
    Builder, Hook, Vm,
};

use crate::backend::{self, Datum, Keep};
use crate::binary::Component;

use anyhow::Result;
use kvm_ioctls::Kvm;

use std::sync::{Arc, RwLock};

pub const SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sev"));

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

    fn shim(&self) -> &'static [u8] {
        SHIM
    }

    fn data(&self) -> Vec<Datum> {
        vec![dev_kvm(), kvm_version()]
    }

    fn build(&self, shim: Component, code: Component) -> Result<Arc<dyn Keep>> {
        let vm = Builder::new(shim, code, builder::Kvm).build::<()>()?.vm()?;

        Ok(Arc::new(RwLock::new(vm)))
    }

    fn measure(&self, shim: Component, code: Component) -> Result<String> {
        let digest = Builder::new(shim, code, builder::Kvm)
            .build::<()>()?
            .measurement()?;

        let json = format!(
            r#"{{ "backend": "kvm", "{}": {:?} }}"#,
            digest.kind, digest.digest
        );
        Ok(json)
    }
}
