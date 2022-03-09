// SPDX-License-Identifier: Apache-2.0

pub mod tls;

mod preview_0;
mod preview_1;

use core::ops::{Deref, DerefMut};
use wasi_common::WasiCtx;

pub struct Ctx {
    pub inner: WasiCtx,
}

impl Deref for Ctx {
    type Target = WasiCtx;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Ctx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
