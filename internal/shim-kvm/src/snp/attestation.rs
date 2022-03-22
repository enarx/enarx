// SPDX-License-Identifier: Apache-2.0

//! SNP attestation and ASN.1 helper functions

/// Header of the SnpReport Response
#[repr(C)]
pub struct SnpReportResponseData {
    /// 0 if valid
    pub status: u32,
    /// size
    pub size: u32,
    rsvd: [u8; 24],
}

/// writes a 6 byte header including a u32 length in big endian
///
/// helper function for ASN.1 encoding
fn asn_len_header(header: &mut [u8], tag: u8, len: usize) -> Option<()> {
    let len: u32 = len.try_into().ok()?;
    header[0] = tag;
    header[1] = 0x84; // 4 bytes of length
    header[2..ASN_LEN_HEADER_SIZE].copy_from_slice(&len.to_be_bytes());
    Some(())
}

const ASN_LEN_HEADER_SIZE: usize = 6;

/// wraps a chunk with a header returning the total length
///
/// helper function for ASN.1 encoding
fn asn_wrap(
    chunks: &mut [u8],
    header_len: usize,
    header: impl Fn(&mut [u8], usize) -> Option<()>,
    body: impl Fn(&mut [u8]) -> Option<usize>,
) -> Option<usize> {
    let (head_chunk, body_chunk) = chunks.split_at_mut(header_len);

    let body_len = body(body_chunk)?;

    header(head_chunk, body_len)?;

    let len = header_len.checked_add(body_len)?;
    Some(len)
}

const ASN_SECTION_CONSTRUCTED: u8 = 0x30;
const ASN_OCTET_STRING: u8 = 0x04;

/// Naive ASN.1 encoding for OID 1.3.6.1.4.1.58270.1.3
pub fn asn1_encode_report_vcek(chunks: &mut [u8], report: &[u8], vcek: &[u8]) -> Option<usize> {
    let section_header =
        |header: &mut [u8], body_len| asn_len_header(header, ASN_SECTION_CONSTRUCTED, body_len);

    let octet_header =
        |header: &mut [u8], body_len| asn_len_header(header, ASN_OCTET_STRING, body_len);

    let report_chunk = |chunks: &mut [u8]| {
        // report data
        chunks[..report.len()].copy_from_slice(report);
        Some(report.len())
    };

    let vcek_report = |chunks: &mut [u8]| {
        // vcek data
        let (vcek_chunk, chunks) = chunks.split_at_mut(vcek.len());
        vcek_chunk.copy_from_slice(vcek);
        let report_chunk_len = asn_wrap(chunks, ASN_LEN_HEADER_SIZE, octet_header, report_chunk)?;
        let len = report_chunk_len.checked_add(vcek.len())?;
        Some(len)
    };

    asn_wrap(chunks, ASN_LEN_HEADER_SIZE, section_header, vcek_report)
}
