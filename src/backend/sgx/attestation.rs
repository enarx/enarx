// SPDX-License-Identifier: Apache-2.0
//
// CREDITS
// * https://github.com/fortanix/rust-sgx for examples of AESM requests.

use super::AESM_SOCKET;
use crate::backend::sgx::{sgx_cache_dir, TCB_PATH};
use crate::protobuf::aesm_proto::{
    Request, Request_GetQuoteExRequest, Request_GetQuoteSizeExRequest,
    Request_GetSupportedAttKeyIDNumRequest, Request_GetSupportedAttKeyIDsRequest,
    Request_InitQuoteExRequest, Response,
};

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;

use anyhow::Context;
use der::{Document, Encode, Sequence};
use protobuf::Message;
use sallyport::item::enarxcall::sgx::TargetInfo;

const SGX_TI_SIZE: usize = size_of::<TargetInfo>();
const AESM_REQUEST_TIMEOUT: u32 = 1_000_000;
const SGX_KEY_ID_SIZE: u32 = 256;
const SGX_REPORT_SIZE: usize = 432;

#[derive(Sequence)]
pub struct SgxEvidence<'a> {
    #[asn1(type = "OCTET STRING")]
    pub quote: &'a [u8],
    // CRL & TCB data are already ASN.1 encoded on disk
    pub crl: Document,
    pub tcb: Document,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AesmError {
    UnexpectedError,
    NoDeviceError,
    ParameterError,
    EpidblobError,
    EpidRevokedError,
    GetLicensetokenError,
    SessionInvalid,
    MaxNumSessionReached,
    PsdaUnavailable,
    EphSessionFailed,
    LongTermPairingFailed,
    NetworkError,
    NetworkBusyError,
    ProxySettingAssist,
    FileAccessError,
    SgxProvisionFailed,
    ServiceStopped,
    Busy,
    BackendServerBusy,
    UpdateAvailable,
    OutOfMemoryError,
    MsgError,
    ThreadError,
    SgxDeviceNotAvailable,
    EnableSgxDeviceFailed,
    PlatformInfoBlobInvalidSig,
    ServiceNotAvailable,
    KdfMismatch,
    OutOfEpc,
    ServiceUnavailable,
    UnrecognizedPlatform,
    EcdsaIdMismatch,
    PathnameBufferOverflowError,
    ErrorStoredKey,
    PubKeyIdMismatch,
    InvalidPceSigScheme,
    AttKeyBlobError,
    UnsupportedAttKeyId,
    UnsupportedLoadingPolicy,
    InterfaceUnavailable,
    PlatformLibUnavailable,
    AttKeyNotInitialized,
    AttKeyCertDataInvalid,
    NoPlatformCertData,
    ErrorReport,
    EnclaveLost,
    InvalidReport,
    EnclaveLoadError,
    UnableToGenerateQeReport,
    KeyCertificationError,
    ConfigUnsupported,
    Unknown(u32),
}

impl From<u32> for AesmError {
    fn from(n: u32) -> AesmError {
        use self::AesmError::*;
        match n {
            1 => UnexpectedError,
            2 => NoDeviceError,
            3 => ParameterError,
            4 => EpidblobError,
            5 => EpidRevokedError,
            6 => GetLicensetokenError,
            7 => SessionInvalid,
            8 => MaxNumSessionReached,
            9 => PsdaUnavailable,
            10 => EphSessionFailed,
            11 => LongTermPairingFailed,
            12 => NetworkError,
            13 => NetworkBusyError,
            14 => ProxySettingAssist,
            15 => FileAccessError,
            16 => SgxProvisionFailed,
            17 => ServiceStopped,
            18 => Busy,
            19 => BackendServerBusy,
            20 => UpdateAvailable,
            21 => OutOfMemoryError,
            22 => MsgError,
            23 => ThreadError,
            24 => SgxDeviceNotAvailable,
            25 => EnableSgxDeviceFailed,
            26 => PlatformInfoBlobInvalidSig,
            27 => ServiceNotAvailable,
            28 => KdfMismatch,
            29 => OutOfEpc,
            30 => ServiceUnavailable,
            31 => UnrecognizedPlatform,
            32 => EcdsaIdMismatch,
            33 => PathnameBufferOverflowError,
            34 => ErrorStoredKey,
            35 => PubKeyIdMismatch,
            36 => InvalidPceSigScheme,
            37 => AttKeyBlobError,
            38 => UnsupportedAttKeyId,
            39 => UnsupportedLoadingPolicy,
            40 => InterfaceUnavailable,
            41 => PlatformLibUnavailable,
            42 => AttKeyNotInitialized,
            43 => AttKeyCertDataInvalid,
            44 => NoPlatformCertData,
            45 => ErrorReport,
            46 => EnclaveLost,
            47 => InvalidReport,
            48 => EnclaveLoadError,
            49 => UnableToGenerateQeReport,
            50 => KeyCertificationError,
            51 => ConfigUnsupported,
            _ => Unknown(n),
        }
    }
}

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
                AesmError::from(res.get_errorCode())
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
            format!(
                "GetSupportedAttKeyIDs: error: {:?}",
                AesmError::from(res.get_errorCode())
            ),
        ));
    }

    let key_ids_blob = res.get_att_key_ids();
    Ok(key_ids_blob
        .chunks_exact(SGX_KEY_ID_SIZE as usize)
        .map(Vec::from)
        .collect())
}

pub fn get_algorithm_id(key_id: &[u8]) -> u32 {
    const ALGORITHM_OFFSET: usize = 154;

    if key_id.len() < ALGORITHM_OFFSET + 4 {
        return u32::MAX;
    }

    let mut bytes: [u8; 4] = Default::default();
    bytes.copy_from_slice(&key_id[ALGORITHM_OFFSET..ALGORITHM_OFFSET + 4]);
    u32::from_le_bytes(bytes)
}

/// Gets Att Key ID
pub fn get_attestation_key_id() -> Result<Vec<u8>, Error> {
    const SGX_QL_ALG_ECDSA_P256: u32 = 2;

    let num_key_ids = get_key_id_num()?;

    if num_key_ids == 0 {
        return Err(Error::new(ErrorKind::Other, "No attestation key IDs"));
    }

    let key_ids = get_key_ids(num_key_ids)?;

    // Select the ECDSA key that will be used later, if ECDSA is not supported the key id is still present - https://github.com/intel/linux-sgx/issues/536
    let ecdsa_key_id = key_ids
        .into_iter()
        .find(|id| SGX_QL_ALG_ECDSA_P256 == get_algorithm_id(id))
        .expect("ECDSA attestation key not available.");

    Ok(ecdsa_key_id)
}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
pub fn get_target_info(akid: Vec<u8>, size: usize, out_buf: &mut [u8]) -> Result<usize, Error> {
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
            format!(
                "InitQuoteExRequest: error: {:?}",
                AesmError::from(res.get_errorCode())
            ),
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
pub fn get_key_size(akid: Vec<u8>) -> Result<usize, Error> {
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
            format!(
                "InitQuoteEx error: {:?}",
                AesmError::from(res.get_errorCode())
            ),
        ));
    }

    Ok(res.get_pub_key_id_size() as usize)
}

/// Gets quote size
pub fn get_quote_size(akid: Vec<u8>) -> Result<usize, Error> {
    let mut transaction = AesmTransaction::new();
    let mut msg = Request_GetQuoteSizeExRequest::new();

    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    msg.set_att_key_id(akid);
    transaction.set_getQuoteSizeExReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_getQuoteSizeExRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "GetQuoteSizeEx error: {:?}",
                AesmError::from(res.get_errorCode())
            ),
        ));
    }

    Ok(res.get_quote_size() as usize)
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
pub fn get_quote(report: &[u8], akid: Vec<u8>, out_buf: &mut [u8]) -> Result<usize, Error> {
    let mut transaction = AesmTransaction::new();

    let mut msg = Request_GetQuoteExRequest::new();
    msg.set_timeout(AESM_REQUEST_TIMEOUT);
    msg.set_report(report[0..SGX_REPORT_SIZE].to_vec());
    msg.set_att_key_id(akid);
    msg.set_buf_size(out_buf.len() as u32);
    transaction.set_getQuoteExReq(msg);

    let pb_msg = transaction.request()?;

    let res = pb_msg.get_getQuoteExRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "GetQuoteEx error: {:?}",
                AesmError::from(res.get_errorCode())
            ),
        ));
    }

    let quote = res.get_quote();

    if quote.len() != out_buf.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "GetQuoteEx: Invalid QUOTE size: {} != {}",
                quote.len(),
                out_buf.len()
            ),
        ));
    }

    out_buf.copy_from_slice(quote);
    Ok(quote.len())
}

/// Gets quote size with CRL added
pub fn get_quote_size_with_collateral(akid: Vec<u8>) -> Result<usize, Error> {
    let q_size = get_quote_size(akid)?;
    let out_buf_temp = vec![0; q_size];

    let mut crl_file = sgx_cache_dir()
        .map_err(|e| Error::new(ErrorKind::Other, format!("SGX CRL read error {e}")))?;
    crl_file.push("crls.der");

    let tcb = Document::read_der_file(TCB_PATH)
        .context(format!("error reading Intel TCB file `{TCB_PATH:?}`"))
        .map_err(|e| Error::new(ErrorKind::Other, format!("DER decoding error: {e}")))?;

    let evidence = SgxEvidence {
        quote: &out_buf_temp,
        crl: Document::read_der_file(&crl_file)
            .context(format!("error reading Intel CRL file {crl_file:?}"))
            .map_err(|e| Error::new(ErrorKind::Other, format!("DER decoding error: {e}")))?,
        tcb,
    };

    let evidence_vec = evidence
        .to_vec()
        .map_err(|e| Error::new(ErrorKind::Other, format!("SGX evidence to DER error: {e}")))?;

    Ok(evidence_vec.len())
}

pub fn get_quote_and_collateral(
    report: &[u8],
    akid: Vec<u8>,
    out_buf: &mut [u8],
) -> Result<usize, Error> {
    // Get the report in a separate buffer
    let q_size = get_quote_size(akid.clone())?;
    let mut out_buf_temp = vec![0; q_size];
    get_quote(report, akid, &mut out_buf_temp)?;

    let mut crl_file = sgx_cache_dir()
        .map_err(|e| Error::new(ErrorKind::Other, format!("SGX CRL read error: {e}")))?;
    crl_file.push("crls.der");

    let crl = Document::read_der_file(&crl_file)
        .context(format!("error reading Intel CRL file `{crl_file:?}`"))
        .map_err(|e| Error::new(ErrorKind::Other, format!("DER decoding error: {e}")))?;

    let tcb = Document::read_der_file(TCB_PATH)
        .context(format!("error reading Intel TCB file `{TCB_PATH:?}`"))
        .map_err(|e| Error::new(ErrorKind::Other, format!("DER decoding error: {e}")))?;

    let evidence = SgxEvidence {
        quote: &out_buf_temp.clone(),
        crl,
        tcb,
    };

    let evidence = evidence.to_vec().map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("SGX CRL & report error {e}"),
        )
    })?;

    if evidence.len() > out_buf.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "SGX CRL & report error: buffer length is {}, but need {}",
                out_buf.len(),
                evidence.len()
            ),
        ));
    }

    out_buf.copy_from_slice(&evidence);

    Ok(evidence.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(
        not(all(host_can_test_sgx, host_can_test_attestation)),
        ignore = "CPU does not support SGX2 or attestation not possible"
    )]
    fn request_target_info() {
        assert!(std::path::Path::new(AESM_SOCKET).exists());

        let mut output = [1u8; SGX_TI_SIZE];

        let akid = get_attestation_key_id().expect(
            "Error obtaining attestation key id. Check your aesmd / pccs service installation.",
        );
        let pkeysize = get_key_size(akid.clone()).expect("error obtaining key size");
        assert_eq!(
            get_target_info(akid, pkeysize, &mut output).unwrap(),
            SGX_TI_SIZE
        );
    }
}
