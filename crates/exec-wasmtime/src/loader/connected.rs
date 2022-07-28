// SPDX-License-Identifier: Apache-2.0

use super::{Completed, Connected, Loader};

use anyhow::{bail, Context, Result};
use wasmtime::Trap;

impl Loader<Connected> {
    pub fn next(self) -> Result<Loader<Completed>> {
        let Self(Connected { mut wstore, linker }) = self;

        let func = linker
            .get_default(&mut wstore, "")
            .context("failed to get default function")?;

        let mut values = vec![wasmtime::Val::null(); func.ty(&wstore).results().len()];
        if let Err(e) = func.call(wstore, Default::default(), &mut values) {
            match e.downcast_ref::<Trap>().map(Trap::i32_exit_status) {
                Some(Some(0)) => {} // function exited with a code of 0, treat as success
                _ => bail!(e.context("failed to execute default function")),
            }
        };
        Ok(Loader(Completed { values }))
    }
}
