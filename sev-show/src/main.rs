// SPDX-License-Identifier: Apache-2.0

//! This program performs various checks in the running system to
//! discover hardware and kernel support for AMD Secure Encrypted
//! Virtualization (SEV) technology. Like its counterpart, `sgx-show`,
//! this program will create a tree-like hierarchy of tests to look
//! for AMD SEV capabilities.
//!
//! Note: this will eventually be superseded by the consolidation
//! of `sgx-show`-like utilities.

mod show;

use core::arch::x86_64::__cpuid_count;

use show::*;

/// Emits the results described in `tests` and prints them in a
/// tree-like fashion.
fn emit_results(tests: Vec<CompletedTest>, indent: usize) {
    use colored::*;

    for test in tests {
        let icon = if test.passed() {
            "✔".green()
        } else {
            "✗".red()
        };
        let info = test.info.clone().unwrap_or("".to_string());

        println!("{:>space$}{} {}{}", "", icon, test, info, space = indent);
        if let Some(dependents) = test.dependents {
            emit_results(dependents, indent + 2);
        }
    }
}

fn main() {
    let cpuid = unsafe { __cpuid_count(0x0000_0000, 0x0000_0000) };
    let enc_mem_caps = unsafe { __cpuid_count(0x8000_001f, 0x0000_0000) };

    let tests = vec![Test {
        name: "AMD CPU",
        func: Box::new(move || {
            let data =
                ((cpuid.ebx as u128) << 64) | ((cpuid.edx as u128) << 32) | (cpuid.ecx as u128);

            // "AuthenticAMD" -- see Table 3.2: Processor Vendor Return Values
            // https://www.amd.com/system/files/TechDocs/24594.pdf
            if data == 0x0000_0000_6874_7541_6974_6E65_444D_4163 as u128 {
                (Ok(()), None)
            } else {
                (Err(()), None)
            }
        }),
        dependents: vec![
            Test {
                name: "SME support",
                func: Box::new(move || {
                    if (enc_mem_caps.eax & (1 << 0)) != 0 {
                        (Ok(()), None)
                    } else {
                        (Err(()), None)
                    }
                }),
                dependents: vec![
                ],
            },
        ],
    }];

    let completed = tests.into_iter().map(|t| t.run()).collect();

    emit_results(completed, 0);
}
