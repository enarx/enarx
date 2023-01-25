// SPDX-License-Identifier: Apache-2.0

//! The Enarx Wasm runtime and all related functionality

mod identity;
mod io;
mod net;

use self::io::null::Null;
use self::io::stdio_file;
use self::net::{connect_file, listen_file};

use super::{Package, Workload};

use anyhow::{bail, Context};
use enarx_config::{Config, File};
use wasi_common::file::FileCaps;
use wasi_common::WasiFile;
use wasmtime::{AsContextMut, Engine, Linker, Module, Store, Trap, Val};
use wasmtime_wasi::stdio::{stderr, stdin, stdout};
use wasmtime_wasi::{add_to_linker, WasiCtxBuilder};
use wiggle::tracing::{instrument, trace_span};

// The Enarx Wasm runtime
pub struct Runtime;

impl Runtime {
    // Execute an Enarx [Package]
    #[instrument]
    pub fn execute(package: Package) -> anyhow::Result<Vec<Val>> {
        let (prvkey, crtreq) =
            identity::generate().context("failed to generate a private key and CSR")?;

        let Workload { webasm, config } = package.try_into()?;
        let Config {
            steward,
            args,
            files,
            env,
        } = config.unwrap_or_default();

        let certs = if let Some(url) = steward {
            identity::steward(&url, crtreq).context("failed to attest to Steward")?
        } else {
            identity::selfsigned(&prvkey).context("failed to generate self-signed certificates")?
        }
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();

        let config = wasmtime::Config::new();
        let engine = trace_span!("initialize Wasmtime engine")
            .in_scope(|| Engine::new(&config))
            .context("failed to create execution engine")?;

        let mut linker = trace_span!("setup linker").in_scope(|| Linker::new(&engine));
        trace_span!("link WASI")
            .in_scope(|| add_to_linker(&mut linker, |s| s))
            .context("failed to setup linker and link WASI")?;

        let mut wstore = trace_span!("initialize Wasmtime store")
            .in_scope(|| Store::new(&engine, WasiCtxBuilder::new().build()));

        let module = trace_span!("compile Wasm")
            .in_scope(|| Module::from_binary(&engine, &webasm))
            .context("failed to compile Wasm module")?;
        trace_span!("link Wasm")
            .in_scope(|| linker.module(&mut wstore, "", &module))
            .context("failed to link module")?;

        let mut ctx = wstore.as_context_mut();
        let ctx = ctx.data_mut();

        let mut names = vec![];
        for (fd, file) in files.iter().enumerate() {
            names.push(file.name());
            let (file, caps): (Box<dyn WasiFile>, _) = match file {
                File::Null(..) => (Box::new(Null), FileCaps::all()),
                File::Stdin(..) => stdio_file(stdin()),
                File::Stdout(..) => stdio_file(stdout()),
                File::Stderr(..) => stdio_file(stderr()),
                File::Listen(file) => listen_file(file, certs.clone(), &prvkey)
                    .context("failed to setup listening socket")?,
                File::Connect(file) => connect_file(file, certs.clone(), &prvkey)
                    .context("failed to setup connection stream")?,
            };
            let fd = fd.try_into().context("too many open files")?;
            ctx.insert_file(fd, file, caps);
        }
        ctx.push_env("FD_COUNT", &names.len().to_string())
            .context("failed to set environment variable `FD_COUNT`")?;
        ctx.push_env("FD_NAMES", &names.join(":"))
            .context("failed to set environment variable `FD_NAMES`")?;

        for (k, v) in env {
            ctx.push_env(&k, &v)
                .context("failed to set environment variable `{k}`")?;
        }

        ctx.push_arg("main.wasm")
            .context("failed to push argv[0]")?;
        for arg in args {
            ctx.push_arg(&arg).context("failed to push argument")?;
        }

        let func = trace_span!("get default function")
            .in_scope(|| linker.get_default(&mut wstore, ""))
            .context("failed to get default function")?;

        let mut values = vec![Val::null(); func.ty(&wstore).results().len()];
        if let Err(e) = trace_span!("execute default function")
            .in_scope(|| func.call(wstore, Default::default(), &mut values))
        {
            match e.downcast_ref::<Trap>().map(Trap::i32_exit_status) {
                Some(Some(0)) => {} // function exited with a code of 0, treat as success
                _ => bail!(e.context("failed to execute default function")),
            }
        };
        Ok(values)
    }
}
