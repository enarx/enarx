// SPDX-License-Identifier: Apache-2.0

use super::{Acquired, Attested, Loader};

use std::{io::Read, os::unix::prelude::FromRawFd};

use anyhow::Result;

impl Loader<Attested> {
    pub fn next(self) -> Result<Loader<Acquired>> {
        // TODO: get workload from drawbridge.

        // FIXME: temporary hack to read wasm from fd 3.
        let mut file = unsafe { std::fs::File::from_raw_fd(3) };
        let mut webasm = Vec::new();
        file.read_to_end(&mut webasm)?;

        Ok(Loader(Acquired {
            config: self.0.config,
            srvcfg: self.0.srvcfg,
            cltcfg: self.0.cltcfg,

            webasm,
        }))
    }
}
