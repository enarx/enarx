// SPDX-License-Identifier: Apache-2.0

// Credit to: https://github.com/fortanix/rust-sgx/tree/master/aesm-client
// for examples of AESM Requests.

use crate::protobuf::aesm_proto::{
    Request, Request_GetQuoteExRequest, Request_GetSupportedAttKeyIDNumRequest,
    Request_GetSupportedAttKeyIDsRequest, Request_InitQuoteExRequest, Response,
    Response_GetQuoteExResponse, Response_InitQuoteExResponse,
};

use sallyport::syscall::{SGX_QUOTE_SIZE, SGX_TI_SIZE};

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::unix::net::UnixStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use protobuf::Message;

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";
const TIMEOUT: u32 = 1_000_000;
const SGX_KEY_ID_SIZE: u32 = 256;

// Specifies the protobuf Request type to communicate with AESMD.
#[derive(Debug)]
enum ReqType {
    AkIdNum,
    AkId,
    TInfo,
    KeySize,
    Quote,
}

impl ReqType {
    fn set_request(
        &self,
        report: Option<&[u8; 432]>,
        akid: Option<Vec<u8>>,
        size: Option<usize>,
    ) -> Result<Request, Error> {
        let mut req = Request::new();

        match self {
            ReqType::AkIdNum => {
                // removed
                unimplemented!()
            }
            ReqType::AkId => {
                // removed
                unimplemented!()
            }
            ReqType::TInfo => {
                let akid = match akid {
                    Some(a) => a,
                    None => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "no attestation key ID provided for setting Init Quote Ex request",
                        ));
                    }
                };
                let size = match size {
                    Some(s) => s,
                    None => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "no key size provided for setting Init Quote Ex request",
                        ));
                    }
                };
                let mut msg = Request_InitQuoteExRequest::new();
                msg.set_timeout(TIMEOUT);
                msg.set_b_pub_key_id(true);
                msg.set_att_key_id(akid);
                msg.set_buf_size(size as u64);
                req.set_initQuoteExReq(msg);
                Ok(req)
            }
            ReqType::KeySize => {
                let akid = match akid {
                    Some(a) => a,
                    None => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "no attestation key ID provided for setting Init Quote Ex request to get key size",
                        ));
                    }
                };
                let mut msg = Request_InitQuoteExRequest::new();
                msg.set_timeout(TIMEOUT);
                msg.set_b_pub_key_id(false);
                msg.set_att_key_id(akid);
                req.set_initQuoteExReq(msg);
                Ok(req)
            }
            ReqType::Quote => {
                let report = match report {
                    Some(r) => r,
                    None => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "no Report provided for setting Get Quote Ex request",
                        ));
                    }
                };
                let akid = match akid {
                    Some(a) => a,
                    None => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "no attestation key ID provided for setting Get Quote Ex request",
                        ));
                    }
                };
                let mut msg = Request_GetQuoteExRequest::new();
                msg.set_timeout(TIMEOUT);
                msg.set_report(report.to_vec());
                msg.set_att_key_id(akid);
                msg.set_buf_size(SGX_QUOTE_SIZE as u32);
                req.set_getQuoteExReq(msg);
                Ok(req)
            }
        }
    }

    fn send_request(&self, req: Request, stream: &mut UnixStream) -> Result<Response, Error> {
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
        buf_wrtr[0..size_of::<u32>()].copy_from_slice(&req_len.to_le_bytes());

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

/// Gets Att Key ID
fn get_ak_id() -> Result<Vec<u8>, Error> {
    let mut stream = UnixStream::connect(AESM_SOCKET)?;

    let r = ReqType::AkIdNum;
    let mut req = Request::new();
    let mut msg = Request_GetSupportedAttKeyIDNumRequest::new();
    msg.set_timeout(TIMEOUT);
    req.set_getSupportedAttKeyIDNumReq(msg);
    let pb_msg: Response = r.send_request(req, &mut stream)?;

    let res = pb_msg.get_getSupportedAttKeyIDNumRes();

    if res.get_errorCode() != 0 {
        panic!(
            "Received error code {:?} in GetSupportedAttKeyIDNum",
            res.get_errorCode()
        );
    }

    let num_key_ids = res.get_att_key_id_num();

    let expected_buffer_size: u32 = num_key_ids * SGX_KEY_ID_SIZE;
    dbg!(num_key_ids);
    assert_eq!(1, num_key_ids);

    let mut stream = UnixStream::connect(AESM_SOCKET)?;

    let r = ReqType::AkId;
    let mut req = Request::new();
    let mut msg = Request_GetSupportedAttKeyIDsRequest::new();
    msg.set_timeout(TIMEOUT);
    msg.set_buf_size(expected_buffer_size);
    req.set_getSupportedAttKeyIDsReq(msg);

    let pb_msg: Response = r.send_request(req, &mut stream)?;

    let res = pb_msg.get_getSupportedAttKeyIDsRes();

    if res.get_errorCode() != 0 {
        panic!(
            "Received error code {:?} in GetSupportedAttKeyIDs",
            res.get_errorCode()
        );
    }

    let key_ids_blob = res.get_att_key_ids();
    let key_ids: Vec<Vec<u8>> = key_ids_blob
        .chunks_exact(SGX_KEY_ID_SIZE as usize)
        .map(Vec::from)
        .collect();

    assert!(!key_ids.is_empty());

    Ok(key_ids.get(0).unwrap().clone())
}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_ti(akid: Vec<u8>, size: usize, out_buf: &mut [u8]) -> Result<usize, Error> {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");

    let mut stream = UnixStream::connect(AESM_SOCKET)?;

    let r = ReqType::TInfo;
    let pb_req = r.set_request(None, Some(akid), Some(size))?;
    let mut pb_msg: Response = r.send_request(pb_req, &mut stream)?;

    let res: Response_InitQuoteExResponse = pb_msg.take_initQuoteExRes();
    let ti = res.get_target_info();

    assert_eq!(
        ti.len(),
        out_buf.len(),
        "Unable to copy TargetInfo to buffer"
    );

    out_buf.copy_from_slice(ti);

    Ok(ti.len())
}

/// Gets key size
fn get_key_size(akid: Vec<u8>) -> Result<usize, Error> {
    let mut stream = UnixStream::connect(AESM_SOCKET)?;

    let r = ReqType::KeySize;
    let pb_req = r.set_request(None, Some(akid), None)?;
    let mut pb_msg: Response = r.send_request(pb_req, &mut stream)?;

    let res: Response_InitQuoteExResponse = pb_msg.take_initQuoteExRes();

    if res.get_errorCode() != 0 {
        panic!(
            "Received error code {:?} in Init Quote Ex Response for key size",
            res.get_errorCode()
        );
    }

    Ok(res.get_pub_key_id_size() as usize)
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
fn get_quote(report: &[u8], akid: Vec<u8>, out_buf: &mut [u8]) -> Result<usize, Error> {
    assert_eq!(
        out_buf.len(),
        SGX_QUOTE_SIZE,
        "Invalid size of output buffer"
    );

    let mut stream = UnixStream::connect(AESM_SOCKET)?;

    let r = ReqType::Quote;
    let mut report_array = [0u8; 432];
    report_array.copy_from_slice(&report[0..432]);
    let req = r.set_request(Some(&report_array), Some(akid), None)?;
    let mut pb_msg = r.send_request(req, &mut stream)?;

    let res: Response_GetQuoteExResponse = pb_msg.take_getQuoteExRes();
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
    out_buf.copy_from_slice(quote);
    dbg!(quote);
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

    // Returns TargetInfo
    if nonce == 0 {
        let akid = get_ak_id().expect("error obtaining att key id");
        let pkeysize = get_key_size(akid.clone()).expect("error obtaining key size");
        let res = get_ti(akid, pkeysize, out_buf);
        dbg!(&res);
        res
    // Returns Quote
    } else {
        dbg!("HELLO");
        let akid = get_ak_id().unwrap();
        let report: &[u8] = unsafe { from_raw_parts(nonce as *const u8, nonce_len) };
        let res = get_quote(report, akid, out_buf);
        dbg!(&res);
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These values were generated by the QE in its TargetInfo.
    const EXPECTED_MRENCLAVE: [u8; 32] = [
        96, 216, 90, 242, 139, 232, 209, 196, 10, 8, 217, 139, 0, 157, 95, 138, 204, 19, 132, 163,
        133, 207, 70, 8, 0, 228, 120, 121, 29, 26, 151, 156,
    ];

    const SAMPLE_REPORT: [u8; 512] = [
        15, 15, 2, 6, 255, 128, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3, 0,
        0, 0, 0, 0, 0, 0, 53, 12, 244, 19, 178, 216, 108, 13, 226, 128, 62, 17, 136, 84, 160, 234,
        114, 79, 206, 50, 26, 104, 135, 230, 61, 162, 75, 160, 62, 93, 17, 20, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 142, 12,
        124, 137, 239, 112, 240, 108, 198, 110, 200, 219, 184, 157, 182, 7, 132, 196, 236, 98, 135,
        85, 216, 184, 203, 101, 55, 254, 171, 182, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        15, 10, 69, 122, 226, 2, 219, 184, 5, 155, 156, 48, 21, 246, 98, 237, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 233, 135, 87, 211, 239, 8, 220, 56, 160, 173, 38, 74, 191,
        131, 181, 168, 241, 128, 248, 59, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 225, 127, 248, 59,
        86, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 234, 225, 127, 248, 59, 86, 0, 0, 190, 15, 1, 0, 0, 0, 0,
        0, 234, 225, 127, 248, 59, 86, 0, 0, 190, 15, 1, 0, 0, 0, 0, 0, 232, 225, 127, 248, 59, 86,
        0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    #[ignore]
    fn req_ti() {
        let output = [1u8; SGX_TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()).unwrap(),
            SGX_TI_SIZE
        );
        assert!(output[0..32].eq(&EXPECTED_MRENCLAVE));
    }

    #[test]
    #[ignore]
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
