// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
#![allow(unknown_lints)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]
// TODO: https://github.com/enarx/enarx/issues/347
#![deny(missing_docs)]
#![allow(missing_docs)]

use sev_types::platform::Build;

pub mod certs;
pub mod firmware;
pub mod launch;
#[cfg(feature = "openssl")]
pub mod session;
