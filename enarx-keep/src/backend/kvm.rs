// SPDX-License-Identifier: Apache-2.0

use crate::backend::{self, Datum, Keep};
use crate::binary::Component;

use kvm_ioctls::Kvm;

use std::io::Result;
use std::path::PathBuf;
use std::sync::Arc;

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
    let version = Kvm::new().and_then(|kvm| Ok(kvm.get_api_version()));
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
    fn data(&self) -> Vec<Datum> {
        vec![dev_kvm(), kvm_version()]
    }

    fn shim(&self) -> Result<PathBuf> {
        unimplemented!()
    }

    fn build(&self, _shim: Component, _code: Component) -> Result<Arc<dyn Keep>> {
        unimplemented!()
    }
}
