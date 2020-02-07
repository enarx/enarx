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
    let tests = vec![Test {
        name: "Stub",
        func: Box::new(|| (Ok(()), None)),
        dependents: vec![],
    }];

    let completed = tests.into_iter().map(|t| t.run()).collect();

    emit_results(completed, 0);
}
