// SPDX-License-Identifier: Apache-2.0

//! The Enarx Wasm runtime and all related functionality

mod identity;
mod io;
mod net;

use self::io::null::Null;
use self::io::stdio_file;
use self::net::{connect_file, create_tls_connector, listen_file};

use super::{Package, Workload};

use anyhow::{bail, Context};
use enarx_config::{Config, File};
use once_cell::sync::Lazy;
use wasi_common::file::FileCaps;
use wasi_common::WasiFile;
use wasmtime::{AsContextMut, Engine, Linker, Module, Store, Trap, Val};
use wasmtime_wasi::stdio::{stderr, stdin, stdout};
use wasmtime_wasi::{add_to_linker, WasiCtxBuilder};

/// Wasmtime config
static WASMTIME_CONFIG: Lazy<wasmtime::Config> = Lazy::new(|| {
    let mut config = wasmtime::Config::new();
    config.wasm_multi_memory(true);
    config.static_memory_maximum_size(0);
    config.static_memory_guard_size(0);
    config.dynamic_memory_guard_size(0);
    config.dynamic_memory_reserved_for_growth(16 * 1024 * 1024);
    config
});

// The Enarx Wasm runtime
pub struct Runtime;

impl Runtime {
    // Execute an Enarx [Package]
    pub fn execute(package: Package) -> anyhow::Result<Vec<Val>> {
        let (prvkey, crtreq) = identity::generate()?;

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

        let engine = Engine::new(&WASMTIME_CONFIG).context("failed to create execution engine")?;

        let mut linker = Linker::new(&engine);
        add_to_linker(&mut linker, |s| s).context("failed to setup linker and add WASI")?;

        linker
            .func_wrap("host", "tls_client_connect", create_tls_connector())
            .expect("failed to add TLS client connect host function");

        let mut wstore = Store::new(&engine, WasiCtxBuilder::new().build());

        let module =
            Module::from_binary(&engine, &webasm).context("failed to compile Wasm module")?;
        linker
            .module(&mut wstore, "", &module)
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

        let func = linker
            .get_default(&mut wstore, "")
            .context("failed to get default function")?;

        let mut values = vec![Val::null(); func.ty(&wstore).results().len()];
        if let Err(e) = func.call(wstore, Default::default(), &mut values) {
            match e.downcast_ref::<Trap>().map(Trap::i32_exit_status) {
                Some(Some(0)) => {} // function exited with a code of 0, treat as success
                _ => bail!(e.context("failed to execute default function")),
            }
        };
        Ok(values)
    }
}
