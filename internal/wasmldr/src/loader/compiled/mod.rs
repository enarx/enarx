// SPDX-License-Identifier: Apache-2.0

mod null;
mod tls;

use null::Null;

use super::{Compiled, Connected, Loader};
use crate::config::{File, Protocol};

use std::net::Ipv4Addr;

use anyhow::Result;
use wasi_common::{file::FileCaps, WasiFile};
use wasmtime::AsContextMut;
use wasmtime_wasi::stdio::{stderr, stdin, stdout};

impl Loader<Compiled> {
    pub fn next(mut self) -> Result<Loader<Connected>> {
        let mut ctx = self.0.wstore.as_context_mut();
        let ctx = ctx.data_mut();

        // Set up environment variables.
        for (k, v) in self.0.config.env.iter() {
            ctx.push_env(k, v)?;
        }

        // Set up the arguments.
        for arg in self.0.config.args.iter() {
            ctx.push_arg(arg)?;
        }

        // Set up the file descriptor environment variables.
        let names: Vec<_> = self.0.config.files.iter().map(|f| f.name()).collect();
        ctx.push_env("FD_COUNT", &names.len().to_string())?;
        ctx.push_env("FD_NAMES", &names.join(":"))?;

        // Set up all the file descriptors.
        for (fd, file) in self.0.config.files.iter().enumerate() {
            let srv = self.0.srvcfg.clone();
            let clt = self.0.cltcfg.clone();

            let (file, mut caps): (Box<dyn WasiFile>, _) = match file {
                File::Null { .. } => (Box::new(Null), FileCaps::all()),
                File::Stdin { .. } => (Box::new(stdin()), FileCaps::all()),
                File::Stdout { .. } => (Box::new(stdout()), FileCaps::all()),
                File::Stderr { .. } => (Box::new(stderr()), FileCaps::all()),

                File::Listen { port, prot, .. } => {
                    let caps = FileCaps::FILESTAT_GET
                        | FileCaps::FDSTAT_SET_FLAGS
                        | FileCaps::POLL_READWRITE
                        | FileCaps::READ;

                    let tcp = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, *port))?;
                    let tcp = cap_std::net::TcpListener::from_std(tcp);
                    match prot {
                        Protocol::Tcp => (wasmtime_wasi::net::Socket::from(tcp).into(), caps),
                        Protocol::Tls => (tls::Listener::new(tcp, srv).into(), caps),
                    }
                }

                File::Connect {
                    host, port, prot, ..
                } => {
                    let caps = FileCaps::FILESTAT_GET
                        | FileCaps::FDSTAT_SET_FLAGS
                        | FileCaps::POLL_READWRITE
                        | FileCaps::READ
                        | FileCaps::WRITE;

                    let tcp = std::net::TcpStream::connect((&**host, *port))?;
                    let tcp = cap_std::net::TcpStream::from_std(tcp);
                    match prot {
                        Protocol::Tcp => (wasmtime_wasi::net::Socket::from(tcp).into(), caps),
                        Protocol::Tls => (tls::Stream::connect(tcp, host, clt)?.into(), caps),
                    }
                }
            };

            // Ensure wasmtime can detect the TTY.
            if file.isatty() {
                caps &= !(FileCaps::TELL | FileCaps::SEEK);
            }

            // Insert the file.
            ctx.insert_file(fd.try_into().unwrap(), file, caps);
        }

        Ok(Loader(Connected {
            wstore: self.0.wstore,
            linker: self.0.linker,
        }))
    }
}
