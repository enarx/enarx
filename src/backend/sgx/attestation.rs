// SPDX-License-Identifier: Apache-2.0

use std::io::{Error, ErrorKind};
use std::slice::from_raw_parts_mut;

const QUOTE_SIZE: usize = 512; // TODO: Determine length of Quote of PCK cert type
const TI_SIZE: usize = 512;
const TMP_TI: [u8; TI_SIZE] = [32u8; TI_SIZE];
const TMP_QUOTE: [u8; QUOTE_SIZE] = [44u8; QUOTE_SIZE];

/// Returns either the size required for the output buffer, or the number of bytes written to the
/// output buffer. Depending on parameters, the output buffer will be filled with the Target Info
/// for the QE, or a Quote verifying a Report.
pub fn get_attestation(
    nonce: usize,
    _nonce_len: usize,
    buf: usize,
    buf_len: usize,
) -> Result<usize, Error> {
    // If the nonce is 0 (NULL), fills the Target Info of the QE into the output buffer
    // and returns the number of bytes written.
    if nonce == 0 {
        // TODO: Populate with real Target Info (https://github.com/enarx/enarx-keepldr/issues/92).
        let b: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

        if b.len() != TMP_TI.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unable to copy TargetInfo to buffer",
            ));
        } else {
            b.copy_from_slice(&TMP_TI);
            return Ok(TI_SIZE);
        }

    // If the nonce in not 0, fills the Quote obtained from the AESMD for the report
    // specified in the nonce field into the output buffer and returns the number of
    // bytes written.
    } else {
        // NOTE: Fill this in with real implementation calling out to AESMD
        // (https://github.com/enarx/enarx-keepldr/issues/92).
        let b: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

        if b.len() != TMP_QUOTE.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unable to copy Quote to buffer",
            ));
        } else {
            b.copy_from_slice(&TMP_QUOTE);
            return Ok(QUOTE_SIZE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const REPORT_SIZE: usize = 512; // TODO: Determine length of Report

    #[test]
    fn req_ti() {
        let output = [1u8; TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()).unwrap(),
            TI_SIZE
        );
        assert_eq!(output, TMP_TI);
    }

    #[test]
    fn req_quote() {
        let input = [1u8; REPORT_SIZE];
        let output = [1u8; QUOTE_SIZE];
        assert_eq!(
            get_attestation(
                input.as_ptr() as usize,
                input.len(),
                output.as_ptr() as usize,
                output.len()
            )
            .unwrap(),
            QUOTE_SIZE
        );
        assert_eq!(output, TMP_QUOTE);
    }
}
