// SPDX-License-Identifier: Apache-2.0

use mmap::Protections;
use sgx_types::page::Flags;

/// Convert `Protections` to `Flags`
pub fn p2f(prot: Protections) -> Flags {
    let mut flags = Flags::empty();

    if prot.contains(Protections::READ) {
        flags |= Flags::R;
    }

    if prot.contains(Protections::WRITE) {
        flags |= Flags::W;
    }

    if prot.contains(Protections::EXEC) {
        flags |= Flags::X;
    }

    flags
}

/// Convert `Flags` to `Protections`
pub fn f2p(flags: Flags) -> Protections {
    let mut prot = Protections::empty();

    if flags.contains(Flags::R) {
        prot |= Protections::READ;
    }

    if flags.contains(Flags::W) {
        prot |= Protections::WRITE;
    }

    if flags.contains(Flags::X) {
        prot |= Protections::EXEC;
    }

    prot
}
