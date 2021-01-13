// SPDX-License-Identifier: Apache-2.0

// Credit to: https://github.com/fortanix/rust-sgx/tree/master/aesm-client
// for examples of AESM Requests.

use crate::protobuf::aesm_proto::{
    Request, Request_GetQuoteRequest, Request_InitQuoteRequest, Response,
    Response_GetQuoteResponse, Response_InitQuoteResponse,
};
use crate::syscall::{SGX_DUMMY_QUOTE, SGX_DUMMY_TI, SGX_QUOTE_SIZE, SGX_TI_SIZE};

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::unix::net::UnixStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use protobuf::Message;

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";
const TIMEOUT: u32 = 1_000_000;

// Specifies the protobuf Request type to communicate with AESMD.
#[derive(Debug)]
enum ReqType {
    TInfo,
    Quote,
}

impl ReqType {
    fn set_request(&self, report: Option<&[u8]>) -> Result<Request, Error> {
        let mut req = Request::new();

        match self {
            ReqType::TInfo => {
                let mut msg = Request_InitQuoteRequest::new();
                msg.set_timeout(TIMEOUT);
                req.set_initQuoteReq(msg);
                Ok(req)
            }
            ReqType::Quote => {
                let report = match report {
                    Some(r) => r,
                    None => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "no Report provided for setting Get Quote request",
                        ));
                    }
                };
                let mut msg = Request_GetQuoteRequest::new();
                msg.set_timeout(TIMEOUT);
                msg.set_report(report[0..432].to_vec());
                msg.set_quote_type(0);
                msg.set_spid([0u8; 16].to_vec());
                msg.set_buf_size(1244);
                req.set_getQuoteReq(msg);
                Ok(req)
            }
        }
    }

    fn send_request(&self, req: Request, mut stream: UnixStream) -> Result<Response, Error> {
        // Set up writer
        let mut buf_wrtr = vec![0u8; size_of::<u32>()];
        match req.write_to_writer(&mut buf_wrtr) {
            Ok(_) => {}
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("invalid protobuf Request: {:?}. Error: {:?}", req, e),
                ));
            }
        }

        let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
        (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

        // Send Request to AESM daemon
        stream.write_all(&buf_wrtr)?;
        stream.flush()?;

        // Receive Response
        let mut res_len_bytes = [0u8; 4];
        stream.read_exact(&mut res_len_bytes)?;
        let res_len = u32::from_le_bytes(res_len_bytes);

        let mut res_bytes = vec![0; res_len as usize];
        stream.read_exact(&mut res_bytes)?;

        Ok(Message::parse_from_bytes(&res_bytes)?)
    }
}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_ti(out_buf: &mut [u8]) -> Result<usize, Error> {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");

    // If unable to connect to the AESM daemon, return dummy value
    let stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(SGX_TI_SIZE);
        }
    };

    let r = ReqType::TInfo;
    let pb_req = r.set_request(None)?;
    let mut pb_msg: Response = r.send_request(pb_req, stream)?;

    let res: Response_InitQuoteResponse = pb_msg.take_initQuoteRes();
    let ti = res.get_targetInfo();

    assert_eq!(
        ti.len(),
        out_buf.len(),
        "Unable to copy TargetInfo to buffer"
    );

    out_buf.copy_from_slice(ti);
    Ok(ti.len())
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
fn get_quote(report: &[u8], out_buf: &mut [u8]) -> Result<usize, Error> {
    assert_eq!(
        out_buf.len(),
        SGX_QUOTE_SIZE,
        "Invalid size of output buffer"
    );

    // If unable to connect to the AESM daemon, return dummy value
    let stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_QUOTE);
            return Ok(SGX_QUOTE_SIZE);
        }
    };

    let r = ReqType::Quote;
    let mut report_array = [0u8; 432];
    report_array.copy_from_slice(&report[0..432]);
    let req = r.set_request(Some(&report_array))?;
    let mut pb_msg = r.send_request(req, stream)?;

    let res: Response_GetQuoteResponse = pb_msg.take_getQuoteRes();
    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Error found in Quote. Error code: {:?}",
                res.get_errorCode()
            ),
        ));
    }
    let quote = res.get_quote();
    if quote.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Error: No data in Quote",
        ));
    }

    assert_eq!(quote.len(), out_buf.len(), "Unable to copy Quote to buffer");
    out_buf.copy_from_slice(&quote);

    Ok(quote.len())
}

/// Returns the number of bytes written to the output buffer. Depending on
/// whether the specified nonce is NULL, the output buffer will be filled with the
/// Target Info for the QE, or a Quote verifying a Report.
pub fn get_attestation(
    nonce: usize,
    nonce_len: usize,
    buf: usize,
    buf_len: usize,
) -> Result<usize, Error> {
    let out_buf: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

    if nonce == 0 {
        get_ti(out_buf)
    } else {
        let report: &[u8] = unsafe { from_raw_parts(nonce as *const u8, nonce_len) };
        get_quote(report, out_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These values were generated by the QE in its TargetInfo.
    const EXPECTED_MRENCLAVE: [u8; 32] = [
        0xb2, 0xc1, 0xfe, 0x35, 0x7d, 0x7b, 0x10, 0x20, 0x54, 0x4f, 0xac, 0x33, 0x64, 0xc3, 0xf9,
        0xb8, 0x98, 0xc1, 0x75, 0x8d, 0xb4, 0x1, 0x1e, 0x9d, 0x65, 0x2e, 0x40, 0xec, 0xd1, 0x86,
        0x14, 0xbc,
    ];

    const SAMPLE_REPORT: [u8; 512] = [
        3, 9, 255, 255, 2, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3, 0,
        0, 0, 0, 0, 0, 0, 22, 58, 88, 16, 125, 53, 233, 100, 17, 24, 200, 65, 26, 64, 74, 60, 66,
        222, 31, 118, 51, 69, 13, 209, 195, 223, 173, 140, 243, 230, 253, 139, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 61, 135,
        106, 93, 83, 83, 127, 211, 215, 39, 124, 55, 194, 56, 135, 20, 122, 50, 245, 219, 208, 129,
        97, 51, 211, 47, 101, 75, 245, 153, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 223, 31,
        156, 246, 241, 143, 199, 153, 178, 215, 41, 71, 144, 22, 86, 106, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 50, 201, 146, 54, 60, 3, 200, 185, 0, 187, 66, 32, 117, 71, 150,
        242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn req_ti() {
        let output = [1u8; SGX_TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()).unwrap(),
            SGX_TI_SIZE
        );
        assert!(output[0..32].eq(&EXPECTED_MRENCLAVE) || output.eq(&SGX_DUMMY_TI));
    }

    #[test]
    fn req_quote() {
        let output = [1u8; SGX_QUOTE_SIZE];
        assert_eq!(
            get_attestation(
                SAMPLE_REPORT.as_ptr() as usize,
                SAMPLE_REPORT.len(),
                output.as_ptr() as usize,
                output.len()
            )
            .unwrap(),
            SGX_QUOTE_SIZE
        );
    }
}
