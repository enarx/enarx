// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use crate::backend::Signatures;
use anyhow::{bail, Result};
#[cfg(windows)]
use enarx_exec_wasmtime::Args;

#[cfg(unix)]
#[derive(Default)]
pub struct Backend;

#[cfg(windows)]
#[derive(Default)]
pub struct Backend(RwLock<Option<Args>>);

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

    #[inline]
    fn configured(&self) -> bool {
        true
    }

    fn data(&self) -> Vec<super::Datum> {
        vec![]
    }
    fn config(&self) -> Vec<super::Datum> {
        vec![]
    }

    #[inline]
    fn keep(
        &self,
        shim: &[u8],
        exec: &[u8],
        _signatures: Option<Signatures>,
    ) -> Result<Arc<dyn super::Keep>> {
        if !shim.is_empty() {
            bail!("The nil backend cannot be called with a shim!")
        }

        if !exec.is_empty() {
            bail!("The nil backend cannot be called with an executable!")
        }

        #[cfg(unix)]
        let thread = Thread;

        #[cfg(windows)]
        let thread = Thread(self.0.write().unwrap().take());

        let ret = Arc::new(RwLock::new(Keep(vec![Box::new(thread)])));

        Ok(ret)
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

    #[cfg(windows)]
    fn set_args(&self, args: Args) {
        self.0.write().unwrap().replace(args);
    }
}

struct Keep(Vec<Box<dyn super::Thread>>);

impl super::Keep for RwLock<Keep> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::Thread>>> {
        Ok(self.write().unwrap().0.pop())
    }
}

#[cfg(unix)]
struct Thread;

#[cfg(windows)]
struct Thread(Option<Args>);

impl super::Thread for Thread {
    fn enter(&mut self, _gdblisten: &Option<String>) -> Result<super::Command> {
        #[cfg(unix)]
        enarx_exec_wasmtime::execute()?;

        #[cfg(windows)]
        enarx_exec_wasmtime::execute_with_args(self.0.take().unwrap())?;

        Ok(super::Command::Exit(0))
    }
}

#[cfg(test)]
mod test {
    use super::Backend;
    use crate::backend::Backend as _;

    #[test]
    fn coverage() {
        let backend = Backend::default();
        assert_eq!(backend.name(), "nil");
        assert!(backend.shim().is_empty());
        assert!(backend.have());
        assert!(backend.data().is_empty());
        assert!(backend.hash(&[], &[]).unwrap().is_empty());
    }
}
