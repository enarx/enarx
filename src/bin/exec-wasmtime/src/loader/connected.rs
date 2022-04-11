// SPDX-License-Identifier: Apache-2.0

use super::{Completed, Connected, Loader};

use anyhow::Result;

impl Loader<Connected> {
    pub fn next(mut self) -> Result<Loader<Completed>> {
        let func = self.0.linker.get_default(&mut self.0.wstore, "")?;

        let mut values = vec![wasmtime::Val::null(); func.ty(&self.0.wstore).results().len()];
        func.call(self.0.wstore, Default::default(), &mut values)?;

        Ok(Loader(Completed { values }))
    }
}
