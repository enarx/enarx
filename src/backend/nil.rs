// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};

pub struct Backend;

impl crate::backend::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "nil"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        &[]
    }

    #[inline]
    fn have(&self) -> bool {
        true
    }

    fn data(&self) -> Vec<super::Datum> {
        vec![]
    }

    #[inline]
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn super::Keep>> {
        if !shim.is_empty() {
            bail!("The nil backend cannot be called with a shim!")
        }

        if !exec.is_empty() {
            bail!("The nil backend cannot be called with an executable!")
        }

        let thread = Thread;

        Ok(Arc::new(RwLock::new(Keep(vec![Box::new(thread)]))))
    }

    #[inline]
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>> {
        if !shim.is_empty() {
            bail!("The nil backend cannot be called with shim!")
        }

        if !exec.is_empty() {
            bail!("The nil backend cannot be called with an executable!")
        }

        Ok(Vec::new())
    }
}

struct Keep(Vec<Box<dyn super::Thread>>);

impl super::Keep for RwLock<Keep> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::Thread>>> {
        Ok(self.write().unwrap().0.pop())
    }
}

struct Thread;

impl super::Thread for Thread {
    fn enter(&mut self, _gdblisten: &Option<String>) -> Result<super::Command> {
        enarx_exec_wasmtime::execute()?;
        Ok(super::Command::Exit(0))
    }
}

#[cfg(test)]
mod test {
    use super::Backend;
    use crate::backend::Backend as _;

    #[test]
    fn coverage() {
        let backend = Backend;
        assert_eq!(backend.name(), "nil");
        assert!(backend.shim().is_empty());
        assert!(backend.have());
        assert!(backend.data().is_empty());
        assert!(backend.hash(&[], &[]).unwrap().is_empty());
    }
}
