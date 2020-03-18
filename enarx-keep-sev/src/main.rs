// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
#![deny(missing_docs)]
// FIXME: remove the #![allow(missing_docs)]
#![allow(missing_docs)]

mod arch;
mod kvmvm;

use kvmvm::SYSCALL_TRIGGER_PORT;

use failure::{Error, ResultExt};
use kvm_ioctls::VcpuExit;
use structopt::StructOpt;

use std::fs::File;
use std::path::PathBuf;
use std::time::Instant;

const PORT_QEMU_EXIT: u16 = 0xF4;

#[derive(StructOpt, Debug)]
struct Args {
    /// The path to the kernel image/binary
    #[structopt(short, long, parse(from_os_str))]
    kernel: PathBuf,
    #[structopt(short, long, parse(from_os_str))]
    app: PathBuf,
}

fn main() {
    let args = Args::from_args();

    if let Err(err) = run(args) {
        let name = std::env::current_exe().expect("Couldn't get executable name");
        let name = name.display();
        eprintln!("{} encountered an error:", name);
        for (level, error) in err.iter_chain().enumerate() {
            eprintln!("#{}: {}", level, error);
        }
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), Error> {
    let kernel_path = args.kernel.clone().into_os_string();
    let kernel =
        File::open(args.kernel).context(format!("Couldn't open kernel image {:?}", kernel_path))?;

    let app_path = args.app.clone().into_os_string();
    let app =
        File::open(args.app).context(format!("Couldn't open application image {:?}", app_path))?;

    eprintln!("Hypervisor: Starting {:?}", kernel_path);
    let start = Instant::now();

    launch_vm(kernel, app)?;

    let elapsed = start.elapsed();
    eprintln!("Hypervisor: Creating and running took {:?}", elapsed);
    eprintln!("Hypervisor: Done");

    Ok(())
}

fn launch_vm(kernel_file: File, app_file: File) -> Result<(), Error> {
    let mut kvm = kvmvm::KvmVm::vm_create_default(kernel_file, app_file, 0)?;

    loop {
        let ret = kvm.cpu_fd.get(0).unwrap().run()?;
        match ret {
            VcpuExit::IoOut(port, data) => match port {
                // Qemu exit simulation
                PORT_QEMU_EXIT if data.eq(&[0x10, 0, 0, 0]) => {
                    // FIXME: we might want to distinguish between EXIT_SUCCESS and EXIT_FAILURE
                    break; // rather than std::process::exit(0)
                }
                PORT_QEMU_EXIT if data.eq(&[0x11, 0, 0, 0]) => {
                    // FIXME: we might want to distinguish between EXIT_SUCCESS and EXIT_FAILURE
                    break; // rather than std::process::exit(1)
                }
                SYSCALL_TRIGGER_PORT => {
                    if let Err(e) = unsafe { kvm.handle_syscall() } {
                        failure::bail!("Handle syscall: {:#?}", e);
                    }
                }
                _ => {
                    let regs = kvm.cpu_fd.get(0).unwrap().get_regs().unwrap();
                    failure::bail!(
                        "Hypervisor: Unexpected IO port {:#X} {:#?}!\n{:#?}",
                        port,
                        data,
                        regs
                    )
                }
            },
            VcpuExit::Hlt => {
                failure::bail!("Hypervisor: VcpuExit::Hlt");
            }
            exit_reason => {
                let regs = kvm.cpu_fd.get(0).unwrap().get_regs().unwrap();
                failure::bail!(
                    "Hypervisor: unexpected exit reason: {:?}\n{:#?}",
                    exit_reason,
                    regs
                );
            }
        }
    }

    Ok(())
}
