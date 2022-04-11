// SPDX-License-Identifier: Apache-2.0

//! `enarx-exec-wasmtime` - the Enarx WebAssembly loader
//!
//! `enarx-exec-wasmtime` is responsible for loading and running WebAssembly modules
//! inside an Enarx keep.
//!
//! Users generally won't execute `enarx-exec-wasmtime` directly, but for test/debugging
//! purposes it can be used to run a .wasm file with given command-line
//! arguments and environment variables.
//!
//! ## Example invocation
//!
//! ```console
//! $ wat2wasm ../tests/wasm/return_1.wat
//! $ RUST_LOG=enarx-exec-wasmtime=info RUST_BACKTRACE=1 cargo run -- return_1.wasm
//!     Finished dev [unoptimized + debuginfo] target(s) in 0.03s
//!      Running `target/x86_64-unknown-linux-musl/debug/enarx-exec-wasmtime return_1.wasm`
//! [INFO  enarx-exec-wasmtime] version 0.2.0 starting up
//! [WARN  enarx-exec-wasmtime] 🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭
//! [INFO  enarx-exec-wasmtime] opts: RunOptions {
//!         envs: [],
//!         module: Some(
//!             "return_1.wasm",
//!         ),
//!         args: [],
//!     }
//! [INFO  enarx-exec-wasmtime] reading module from "return_1.wasm"
//! [INFO  enarx-exec-wasmtime] running workload
//! [WARN  enarx-exec-wasmtime::workload] inheriting stdio from calling process
//! [INFO  enarx-exec-wasmtime] got result: Ok(
//!         [
//!             I32(
//!                 1,
//!             ),
//!         ],
//!     )
//! ```
//!
//! If no filename is given, `enarx-exec-wasmtime` expects to read the WebAssembly module
//! from file descriptor 3, so this would be equivalent:
//! ```console
//! $ RUST_LOG=enarx-exec-wasmtime=info RUST_BACKTRACE=1 cargo run -- 3< return_1.wasm
//!  ```
//!
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]
#![feature(core_ffi_c)]

mod config;
mod loader;

use config::Config;
use loader::Loader;

use std::fs::File;
use std::io::Read;
use std::mem::forget;
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::AsRawFd;

// v0.1.0 KEEP-CONFIG HACK
// We don't yet have a well-defined way to pass runtime configuration from
// the frontend/CLI into the keep, so the keep configuration is pre-defined:
//   * the .wasm module is open on fd3 and gets no arguments or env vars
//   * stdin, stdout, and stderr are enabled and should go to fd 0,1,2
//   * logging should be turned on at "debug" level, output goes to stderr
//

use clap::Parser;
use std::path::PathBuf;

/// Set FSBASE
///
/// Overwrite the only location in musl, which uses the `arch_prctl` syscall
#[no_mangle]
pub extern "C" fn __set_thread_area(p: *mut std::ffi::c_void) -> std::ffi::c_int {
    let mut rax: usize = 0;
    if unsafe { core::arch::x86_64::__cpuid(7).ebx } & 1 == 1 {
        unsafe {
            std::arch::asm!("wrfsbase {}", in(reg) p);
        }
    } else {
        const ARCH_SET_FS: std::ffi::c_int = 0x1002;
        unsafe {
            std::arch::asm!(
            "syscall",
            inlateout("rax")  libc::SYS_arch_prctl => rax,
            in("rdi") ARCH_SET_FS,
            in("rsi") p,
            lateout("rcx") _, // clobbered
            lateout("r11") _, // clobbered
            );
        }
    }
    rax as _
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_name = "MODULE", parse(from_os_str))]
    pub module: Option<PathBuf>,

    #[clap(short, long, value_name = "CONFIG", parse(from_os_str))]
    pub config: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    // KEEP-CONFIG HACK: we've inherited stdio and the shim sets
    // "RUST_LOG=debug", so this should make logging go to stderr.
    // FUTURE: we should have a keep-provided debug channel where we can
    // (safely, securely) send logs. Might need our own logger for that..
    env_logger::Builder::from_default_env().init();

    let args = Args::parse();

    let mut config = match (args.module, args.config) {
        (Some(module), Some(config)) => {
            let module = File::open(&module).expect("unable to open file");
            let config = File::open(&config).expect("unable to open file");
            assert_eq!(3, module.as_raw_fd());
            forget(module); // Leak fd 3.
            config
        }

        (None, None) => unsafe { File::from_raw_fd(4) },
        _ => panic!("this configuration is unsupported"),
    };

    let mut buffer = String::new();
    let config: Config = match config.read_to_string(&mut buffer) {
        Ok(..) => toml::from_str(&buffer)?,
        Err(..) => Config::default(),
    };

    // Step through the state machine.
    let configured = Loader::from(config);
    let requested = configured.next()?;
    let attested = requested.next()?;
    let acquired = attested.next()?;
    let compiled = acquired.next()?;
    let connected = compiled.next()?;
    let completed = connected.next()?;

    drop(completed);
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::loader::Loader;

    const NO_EXPORT_WAT: &str = r#"(module
      (memory (export "") 1)
    )"#;

    const RETURN_1_WAT: &str = r#"(module
      (func (export "") (result i32) i32.const 1)
    )"#;

    const HELLO_WASI_WAT: &str = r#"(module
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $__wasi_proc_exit (param i32)))
      (import "wasi_snapshot_preview1" "fd_write"
        (func $__wasi_fd_write (param i32 i32 i32 i32) (result i32)))
      (func $_start
        (i32.store (i32.const 24) (i32.const 14))
        (i32.store (i32.const 20) (i32.const 0))
        (block
          (br_if 0
            (call $__wasi_fd_write
              (i32.const 1)
              (i32.const 20)
              (i32.const 1)
              (i32.const 16)))
          (br_if 0 (i32.ne (i32.load (i32.const 16)) (i32.const 14)))
          (br 1)
        )
        (call $__wasi_proc_exit (i32.const 1))
      )
      (memory 1)
      (export "memory" (memory 0))
      (export "_start" (func $_start))
      (data (i32.const 0) "Hello, world!\0a")
    )"#;

    #[test]
    fn workload_run_return_1() {
        let bytes = wat::parse_str(RETURN_1_WAT).expect("error parsing wat");

        let results: Vec<i32> = Loader::run(&bytes)
            .unwrap()
            .iter()
            .map(wasmtime::Val::unwrap_i32)
            .collect();

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn workload_run_no_export() {
        let bytes = wat::parse_str(NO_EXPORT_WAT).expect("error parsing wat");

        match Loader::run(&bytes) {
            Err(..) => (),
            _ => panic!("unexpected success"),
        }
    }

    #[test]
    fn workload_run_hello_wasi() {
        let bytes = wat::parse_str(HELLO_WASI_WAT).expect("error parsing wat");
        let values = Loader::run(&bytes).unwrap();
        assert_eq!(values.len(), 0);

        // TODO/FIXME: we need a way to configure WASI stdout so we can capture
        // and check it here...
    }
}
