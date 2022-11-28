// SPDX-License-Identifier: Apache-2.0

//! Host function to open a TLS client connection at runtime.

use std::io::ErrorKind;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::Error;
use enarx_config::ConnectFile;
use wasi_common::{snapshots::preview_1::types::Errno, WasiCtx};
use wasmtime::{Caller, Extern, Trap};
use zeroize::Zeroizing;

use super::connect_file;

struct FdLedger {
    last: AtomicU32,
}

impl FdLedger {
    pub fn new() -> Self {
        Self {
            last: AtomicU32::new(3),
        }
    }

    pub fn next_fd(&self, ctx: &WasiCtx) -> Option<u32> {
        let started = match self.last.fetch_add(1, Ordering::SeqCst) {
            0 => 1,
            x => x,
        };
        let mut current = started;
        while ctx.table.contains_key(current) {
            current = self.last.fetch_add(1, Ordering::Relaxed);
            if current == 0 {
                continue;
            } else if current == started {
                return None;
            }
        }
        Some(current)
    }
}

/// Reads `len` bytes from guest memory located at `ptr`.
fn read<T>(caller: &mut Caller<'_, T>, ptr: i32, len: i32) -> Result<Vec<u8>, Trap> {
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(mem)) => mem,
        _ => return Err(Trap::new("could not read from memory")),
    };
    let data = mem
        .data(&caller)
        .get(ptr as u32 as usize..)
        .and_then(|arr| arr.get(..len as u32 as usize));
    data.map(|x| x.to_vec())
        .ok_or_else(|| Trap::new("given memory location out of bounds"))
}

/// Writes `data` to guest memory at `ptr`.
fn write<T>(caller: &mut Caller<'_, T>, ptr: i32, data: &[u8]) -> Result<(), Trap> {
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(mem)) => mem,
        _ => return Err(Trap::new("could not write to memory")),
    };
    if let Some(arr) = mem
        .data_mut(caller)
        .get_mut(ptr as u32 as usize..)
        .and_then(|arr| arr.get_mut(..data.len()))
    {
        arr.copy_from_slice(data);
        Ok(())
    } else {
        Err(Trap::new("write out of bounds"))
    }
}

pub fn create_tls_connector(
) -> impl Fn(Caller<'_, WasiCtx>, i32, i32, u32, i32, i32, i32, i32, i32) -> Result<i32, Trap> {
    let ledger = FdLedger::new();

    move |mut caller: Caller<'_, WasiCtx>,
          host_ptr: i32,
          host_len: i32,
          port: u32,
          cert_ptr: i32,
          cert_len: i32,
          key_ptr: i32,
          key_len: i32,
          fd_ptr: i32| {
        let raw_host = match read(&mut caller, host_ptr, host_len) {
            Ok(host) => host,
            Err(err) => return Err(err),
        };
        let host = match std::str::from_utf8(&raw_host) {
            Ok(x) => x.to_string(),
            Err(_) => return errno(Errno::Inval),
        };
        let port = match port.try_into() {
            Ok(port) => port,
            Err(_) => return errno(Errno::Inval),
        };
        let cert = match read(&mut caller, cert_ptr, cert_len) {
            Ok(cert) => cert,
            Err(err) => return Err(err),
        };
        let key = match read(&mut caller, key_ptr, key_len) {
            Ok(key) => Zeroizing::new(key),
            Err(err) => return Err(err),
        };
        let file = ConnectFile::Tls {
            name: None,
            host,
            port,
        };
        let certs = vec![rustls::Certificate(cert)];
        let (file, caps) = match connect_file(&file, certs, &key) {
            Ok(x) => x,
            Err(err) => return errno(to_errno(err)),
        };
        let fd = match ledger.next_fd(caller.data()) {
            Some(fd) => fd,
            None => return errno(Errno::Nfile),
        };

        let ctx = caller.data_mut();
        ctx.insert_file(fd, file, caps);

        let fd_data = fd.to_le_bytes();
        write(&mut caller, fd_ptr, &fd_data).and_then(|_| errno(Errno::Success))
    }
}

fn errno(errno: Errno) -> Result<i32, Trap> {
    let value: u16 = errno.into();
    Ok(value.into())
}

fn to_errno(error: Error) -> Errno {
    match error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .map(|e| e.kind())
    {
        Some(ErrorKind::ConnectionAborted) => Errno::Connaborted,
        Some(ErrorKind::ConnectionRefused) => Errno::Connrefused,
        Some(ErrorKind::ConnectionReset) => Errno::Connreset,
        Some(ErrorKind::Interrupted) => Errno::Intr,
        Some(ErrorKind::NotConnected) => Errno::Notconn,
        Some(ErrorKind::Unsupported) => Errno::Notsup,
        _ => Errno::Connrefused,
    }
}

#[cfg(test)]
mod test {
    use anyhow::Context;
    use rustls_pemfile::Item::*;
    use std::fmt::Write;
    use std::io::{BufReader, Seek, Write as OtherWrite};
    #[cfg(unix)]
    use std::os::unix::io::IntoRawFd;
    use tempfile::tempfile;
    use wasmtime::Val;
    use wasmtime_wasi::WasiCtxBuilder;

    use crate::{runtime::Runtime, Package};

    use super::FdLedger;

    const IMPORT_CONNECT_WAT: &str = r#"(module
        (import "host" "tls_client_connect"
            (func (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32))
        )
        (func $_start)
        (memory 1)
        (export "memory" (memory 0))
        (export "_start" (func $_start))
    )"#;

    fn gen_connect_wat(key: &[u8]) -> String {
        format!(
            r#"(module
            (import "host" "tls_client_connect"
                (func $c (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32))
            )
            (func $_start (result i32)
                (call $c
                    (i32.const 0)
                    (i32.const 9)
                    (i32.const 443)
                    (i32.const 0)
                    (i32.const 0)
                    (i32.const 16)
                    (i32.const {})
                    (i32.const 0)))
            (memory 1)
            (export "memory" (memory 0))
            (export "_start" (func $_start))
            (data (i32.const 0) "enarx.dev")
            (data (i32.const 16) "{}")
            )"#,
            key.len(),
            to_literal(key)
        )
    }

    fn run(wasm: &[u8]) -> anyhow::Result<Vec<Val>> {
        let mut file = tempfile().context("failed to create module file")?;
        file.write(wasm).context("failed to write module to file")?;
        file.rewind().context("failed to rewind file")?;
        #[cfg(unix)]
        let file = file.into_raw_fd();
        Runtime::execute(Package::Local {
            wasm: file,
            conf: None,
        })
    }

    #[test]
    fn tls_client_connect_can_be_imported() {
        let bytes = wat::parse_str(IMPORT_CONNECT_WAT).expect("error parsing wat");

        let result = run(&bytes).unwrap();
        assert_eq!(result.is_empty(), true);
    }

    #[test]
    fn tls_client_connect_connects_to_enarx_dev() {
        let key = match rustls_pemfile::read_one(&mut BufReader::new(
            include_bytes!("../../../../../tests/data/tls/client.key").as_slice(),
        ))
        .expect("failed to read client TLS certificate key")
        .expect("client TLS certificate key missing")
        {
            RSAKey(buf) | PKCS8Key(buf) | ECKey(buf) => buf,
            item => panic!("Unsupported key type: '{:?}'", item),
        };
        let bytes = wat::parse_str(gen_connect_wat(&key)).expect("error parsing wat");

        let result: Vec<i32> = run(&bytes).unwrap().iter().map(Val::unwrap_i32).collect();
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn ledger_returns_first_free_fd() {
        let ledger = FdLedger::new();
        let mut ctx = WasiCtxBuilder::new().build();
        ctx.table().insert_at(4, Box::new(()));

        let first_fd = ledger.next_fd(&ctx);
        let second_fd = ledger.next_fd(&ctx);

        assert_eq!(first_fd, Some(3));
        assert_eq!(second_fd, Some(5));
    }

    fn to_literal(data: &[u8]) -> String {
        let mut result = String::with_capacity(3 * data.len());
        for byte in data {
            write!(result, "\\{:02x}", byte).unwrap();
        }
        result
    }
}
