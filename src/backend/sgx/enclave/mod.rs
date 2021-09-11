// SPDX-License-Identifier: Apache-2.0

//! # Overview of an Enclave
//!
//! Enclaves are constructed from:
//!
//!   1. One or more pages of code and data. This is the enclave contents.
//!
//!   2. One or more State Save Area (SSA) frames per thread. Each SSA frame
//!      enables one layer of exception handling. During an exception, the
//!      CPU performs an asynchronous enclave exit (AEX) where it store the
//!      CPU state in the current SSA frame (CSSA) and then exits.
//!
//!   3. One Thread Control Structure (TCS) page per thread. Inside the
//!      enclave, this page is accessed exclusively by the hardware. Each
//!      TCS page contains the location and number of the thread's SSA
//!      frames as well as the address of the enclave to jump to when
//!      entering (i.e. the entry point).
//!
//! # Building an Enclave
//!
//! This `Builder` object will help you construct an enclave. First, you will
//! instantiate the `Builder` using `Builder::new()` or `Builder::new_at()`.
//! Next, you will add all the relevant pages using the `Loader::load()`
//! trait method. Finally, you will call `Builder::build()` to verify the
//! enclave signature and finalize the enclave construction.
//!
//! # Executing an Enclave
//!
//! Once you have built an `Enclave` you will want to execute it. This is done
//! by creating a new `Thread` object using `Enclave::spawn()`. Once you have
//! a `Thread` object, you can use `Thread::enter()` to enter the enclave,
//! passing the specified registers. When the enclave returns, you can read
//! the register state from the same structure.
//!
//! # Additional Information
//!
//! The Intel SGX documentation is available [here]. Section references in
//! further documentation refer to this document.
//!
//! [here]: https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

mod builder;
mod execute;
mod ioctls;

pub use builder::Builder;
pub use execute::{Entry, ExceptionInfo, InterruptVector, Registers};

use std::sync::{Arc, RwLock};

use mmarinus::{perms, Map};
use vdso::Symbol;

/// A full initialized enclave
///
/// To begin execution in this enclave, create a new `Thread` object using
/// `Enclave::spawn()`.
pub struct Enclave {
    _mem: Map<perms::Unknown>,
    tcs: RwLock<Vec<usize>>,
}

impl Enclave {
    /// Create a new thread of execuation for an enclave.
    ///
    /// Note that this method does not create a system thread. If you want to
    /// execute multiple enclave threads in parallel, you'll need to spawn
    /// operating system threads in addition to this thread object.
    pub fn spawn(self: Arc<Enclave>) -> Option<Thread> {
        let fnc = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found");

        let tcs = self.tcs.write().unwrap().pop()?;
        Some(Thread {
            enc: self,
            tcs,
            fnc,
        })
    }
}

/// A single thread of execution inside an enclave
///
/// You can begin enclave execution using `Thread::enter()`.
pub struct Thread {
    enc: Arc<Enclave>,
    tcs: usize,
    fnc: &'static Symbol,
}

impl Drop for Thread {
    fn drop(&mut self) {
        self.enc.tcs.write().unwrap().push(self.tcs)
    }
}
