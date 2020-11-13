// SPDX-License-Identifier: Apache-2.0

use crate::syscall::{SGX_DUMMY_QUOTE, SGX_DUMMY_TI, SGX_QUOTE_SIZE, SGX_TI_SIZE};

use std::slice::from_raw_parts_mut;

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
// TODO: Replace synthetic TargetInfo with real TargetInfo.
fn get_ti(out_buf: &mut [u8]) -> usize {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");
    out_buf.copy_from_slice(&SGX_DUMMY_TI);
    SGX_TI_SIZE
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
// TODO: Replace synthetic Quote with real Quote.
fn get_quote(_report: &[u8], out_buf: &mut [u8]) -> usize {
    assert_eq!(
        out_buf.len(),
        SGX_QUOTE_SIZE,
        "Invalid size of output buffer"
    );
    out_buf.copy_from_slice(&SGX_DUMMY_QUOTE);
    SGX_QUOTE_SIZE
}

/// Returns the number of bytes written to the output buffer. Depending on
/// whether the specified nonce is NULL, the output buffer will be filled with the
/// Target Info for the QE, or a Quote verifying a Report.
pub fn get_attestation(nonce: usize, _nonce_len: usize, buf: usize, buf_len: usize) -> usize {
    let out_buf: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

    if nonce == 0 {
        get_ti(out_buf)
    } else {
        let tmp_report = [0u8; 512];
        get_quote(&tmp_report, out_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const REPORT_SIZE: usize = 432;

    #[test]
    fn req_ti() {
        let output = [1u8; SGX_TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()),
            SGX_TI_SIZE
        );
        assert_eq!(output, SGX_DUMMY_TI);
    }

    #[test]
    fn req_quote() {
        let input = [1u8; REPORT_SIZE];
        let output = [1u8; SGX_QUOTE_SIZE];
        assert_eq!(
            get_attestation(
                input.as_ptr() as usize,
                input.len(),
                output.as_ptr() as usize,
                output.len()
            ),
            SGX_QUOTE_SIZE
        );
        assert_eq!(output, SGX_DUMMY_QUOTE);
    }
}
