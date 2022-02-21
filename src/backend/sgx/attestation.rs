// SPDX-License-Identifier: Apache-2.0
//
// CREDITS
// * https://github.com/fortanix/rust-sgx for examples of AESM requests.

use crate::protobuf::aesm_proto::{
    Request, Request_GetQuoteExRequest, Request_GetSupportedAttKeyIDNumRequest,
    Request_GetSupportedAttKeyIDsRequest, Request_InitQuoteExRequest, Response,
};

use std::io::{Error, ErrorKind, Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use protobuf::Message;
use sallyport::syscall::{SGX_QUOTE_SIZE, SGX_TI_SIZE};

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";
const AESM_REQUEST_TIMEOUT: u32 = 1_000_000;
const SGX_KEY_ID_SIZE: u32 = 256;
const SGX_REPORT_SIZE: usize = 432;

struct AesmTransaction(Request);

impl Deref for AesmTransaction {
    type Target = Request;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AesmTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AesmTransaction {
    fn new() -> Self {
        Self(Request::new())
    }

    fn request(&self) -> Result<Response, Error> {
        let mut request = Vec::<u8>::new();

        self.write_to_vec(&mut request).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Invalid protobuf request: {:?}. Error: {:?}", self.0, e),
            )
        })?;

        let mut stream = UnixStream::connect(AESM_SOCKET)?;

        let request_len = request.len() as u32;

        // AESM daemon requires the length prepended before the request.
        stream.write_all(&request_len.to_le_bytes())?;
        stream.write_all(&request)?;
        stream.flush()?;

        let mut response_len_bytes = [0u8; 4];
        stream.read_exact(&mut response_len_bytes)?;
        let response_len = u32::from_le_bytes(response_len_bytes);

        let mut response_bytes = vec![0; response_len as usize];
        stream.read_exact(&mut response_bytes)?;

        let response = Message::parse_from_bytes(&response_bytes)?;

        Ok(response)
    }
}

fn get_key_id_num() -> Result<u32, Error> {
    let mut transaction = AesmTransaction::new();

    let mut msg = Request_GetSupportedAttKeyIDNumRequest::new();
    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    transaction.set_getSupportedAttKeyIDNumReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_getSupportedAttKeyIDNumRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "Received error code {:?} in GetSupportedAttKeyIDNum",
                res.get_errorCode()
            ),
        ));
    }

    Ok(res.get_att_key_id_num())
}

fn get_key_ids(num_key_ids: u32) -> Result<Vec<Vec<u8>>, Error> {
    let expected_buffer_size = num_key_ids * SGX_KEY_ID_SIZE;

    let mut transaction = AesmTransaction::new();

    let mut msg = Request_GetSupportedAttKeyIDsRequest::new();
    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    msg.set_buf_size(expected_buffer_size);
    transaction.set_getSupportedAttKeyIDsReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_getSupportedAttKeyIDsRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("GetSupportedAttKeyIDs: error: {:?}", res.get_errorCode()),
        ));
    }

    let key_ids_blob = res.get_att_key_ids();
    Ok(key_ids_blob
        .chunks_exact(SGX_KEY_ID_SIZE as usize)
        .map(Vec::from)
        .collect())
}

/// Gets Att Key ID
fn get_attestation_key_id() -> Result<Vec<u8>, Error> {
    let num_key_ids = get_key_id_num()?;
    if num_key_ids != 1 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Unexpected number of key IDs: {} != 1", num_key_ids),
        ));
    }

    let key_ids = get_key_ids(num_key_ids)?;

    if key_ids.len() != 1 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "GeSupportedAttKeyIDs: invalid count: {} != 1",
                key_ids.len()
            ),
        ));
    }

    let akid = key_ids.get(0).unwrap().clone();

    Ok(akid)
}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_target_info(akid: Vec<u8>, size: usize, out_buf: &mut [u8]) -> Result<usize, Error> {
    if out_buf.len() != SGX_TI_SIZE {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "Invalid output buffer size: {} != {}",
                out_buf.len(),
                SGX_TI_SIZE
            ),
        ));
    }

    let mut transaction = AesmTransaction::new();
    let mut msg = Request_InitQuoteExRequest::new();

    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    msg.set_b_pub_key_id(true);
    msg.set_att_key_id(akid);
    msg.set_buf_size(size as _);
    transaction.set_initQuoteExReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_initQuoteExRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("InitQuoteExRequest: error: {:?}", res.get_errorCode()),
        ));
    }

    let ti = res.get_target_info();

    if ti.len() != SGX_TI_SIZE {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "InitQuoteEx: Invalid TARGETINFO size: {} != {}",
                ti.len(),
                SGX_TI_SIZE
            ),
        ));
    }

    out_buf.copy_from_slice(ti);

    Ok(ti.len())
}

/// Gets key size
fn get_key_size(akid: Vec<u8>) -> Result<usize, Error> {
    let mut transaction = AesmTransaction::new();
    let mut msg = Request_InitQuoteExRequest::new();

    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    msg.set_b_pub_key_id(false);
    msg.set_att_key_id(akid);
    transaction.set_initQuoteExReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_initQuoteExRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("InitQuoteEx error: {:?}", res.get_errorCode()),
        ));
    }

    Ok(res.get_pub_key_id_size() as usize)
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
fn get_quote(report: &[u8], akid: Vec<u8>, out_buf: &mut [u8]) -> Result<usize, Error> {
    if out_buf.len() != SGX_QUOTE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid size of output buffer {} != {}",
                out_buf.len(),
                SGX_QUOTE_SIZE
            ),
        ));
    }

    let mut transaction = AesmTransaction::new();

    let mut msg = Request_GetQuoteExRequest::new();
    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    msg.set_report(report[0..SGX_REPORT_SIZE].to_vec());
    msg.set_att_key_id(akid);
    msg.set_buf_size(SGX_QUOTE_SIZE as u32);
    transaction.set_getQuoteExReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_getQuoteExRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("GetQuoteEx error: {:?}", res.get_errorCode()),
        ));
    }

    let quote = res.get_quote();

    if quote.len() != SGX_QUOTE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "GetQuoteEx: Invalid QUOTE size: {} != {}",
                quote.len(),
                SGX_QUOTE_SIZE
            ),
        ));
    }

    out_buf.copy_from_slice(quote);
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
    let out_buf = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

    let akid = get_attestation_key_id().expect("error obtaining attestation key id");

    if nonce == 0 {
        let pkeysize = get_key_size(akid.clone()).expect("error obtaining key size");
        get_target_info(akid, pkeysize, out_buf)
    } else {
        let report: &[u8] = unsafe { from_raw_parts(nonce as *const u8, nonce_len) };
        get_quote(report, akid, out_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(host_can_test_sgx), ignore)]
    fn request_target_info() {
        assert_eq!(std::path::Path::new(AESM_SOCKET).exists(), true);

        let output = [1u8; SGX_TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()).unwrap(),
            SGX_TI_SIZE
        );
    }
}
