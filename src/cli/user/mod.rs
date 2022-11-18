// SPDX-License-Identifier: Apache-2.0

mod info;
mod login;
mod logout;
mod register;

use std::env::{var, VarError};

use anyhow::bail;
use clap::Subcommand;

/// Commands for working with users on an Enarx package host.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    #[clap(hide = true)]
    Info(info::Options),
    Login(login::Options),
    #[clap(hide = true)]
    Logout(logout::Options),
    Register(register::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Login(cmd) => cmd.execute(),
            Self::Logout(cmd) => cmd.execute(),
            Self::Register(cmd) => cmd.execute(),
        }
    }
}

pub fn oidc_client_secret() -> anyhow::Result<Option<String>> {
    match var("ENARX_OIDC_CLIENT_SECRET") {
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(e)) => bail!(
            "`ENARX_OIDC_CLIENT_SECRET` value of `{}` is not valid unicode",
            e.to_string_lossy()
        ),
        Ok(secret) => Ok(Some(secret)),
    }
}
