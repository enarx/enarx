// SPDX-License-Identifier: Apache-2.0

mod builder;
pub mod shim;
mod vm;

pub const SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sev"));

pub use vm::{Arch, Builder, Hook, Hv2GpFn, Vm, X86};

use crate::backend::{self, Datum, Keep};
use crate::binary::Component;

use anyhow::Result;
use kvm_ioctls::Kvm;
use openssl::hash::MessageDigest;

use std::path::Path;
use std::sync::{Arc, RwLock};

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

    fn build(&self, code: Component, _sock: Option<&Path>) -> Result<Arc<dyn Keep>> {
        let shim = Component::from_bytes(SHIM)?;

        let vm = Builder::new(shim, code, builder::Kvm).build::<X86>()?.vm();

        Ok(Arc::new(RwLock::new(vm)))
    }

    fn measure(&self, code: Component) -> Result<String> {
        let shim = Component::from_bytes(SHIM)?;

        let digest = Builder::new(shim, code, builder::Kvm)
            .build::<X86>()?
            .measurement(MessageDigest::null())?;

        let json = format!(r#"{{ "backend": "kvm", "null": {:?} }}"#, digest);
        Ok(json)
    }
}
