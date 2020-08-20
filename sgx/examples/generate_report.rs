// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "asm"))]
fn main() {}

#[cfg(feature = "asm")]
fn main() {
    use sgx::attestation_types::ti;

    let target_info: ti::TargetInfo = Default::default();
    let data = ti::ReportData([0u8; 64]);
    let report = unsafe { target_info.get_report(&data) };
    println!("report: {:?}", report);
}
