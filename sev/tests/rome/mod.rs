// SPDX-License-Identifier: Apache-2.0

mod ark;
mod ask;
mod cek;
mod oca;
mod pdh;
mod pek;

const OCA: &[u8] = include_bytes!("oca.cert");
const CEK: &[u8] = include_bytes!("cek.cert");
const PEK: &[u8] = include_bytes!("pek.cert");
const PDH: &[u8] = include_bytes!("pdh.cert");

use ::sev::certs::*;
use codicon::{Decoder, Encoder};
