// SPDX-License-Identifier: Apache-2.0

use std::convert::{Into, TryFrom};

use ::sev::certs::*;
use codicon::Decoder;

pub enum Generation {
    Naples,
    Rome,
}

impl Into<ca::Chain> for Generation {
    fn into(self) -> ca::Chain {
        let (ark, ask) = match self {
            Generation::Naples => (builtin::naples::ARK, builtin::naples::ASK),
            Generation::Rome => (builtin::rome::ARK, builtin::rome::ASK),
        };

        ca::Chain {
            ask: ca::Certificate::decode(&mut &ask[..], ()).unwrap(),
            ark: ca::Certificate::decode(&mut &ark[..], ()).unwrap(),
        }
    }
}

impl TryFrom<&sev::Chain> for Generation {
    type Error = ();
    fn try_from(schain: &sev::Chain) -> Result<Self, Self::Error> {
        let naples: ca::Chain = Generation::Naples.into();
        let rome: ca::Chain = Generation::Rome.into();

        Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
            Generation::Naples
        } else if (&rome.ask, &schain.cek).verify().is_ok() {
            Generation::Rome
        } else {
            return Err(());
        })
    }
}
