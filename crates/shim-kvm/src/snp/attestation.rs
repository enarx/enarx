// SPDX-License-Identifier: Apache-2.0

//! SNP attestation and ASN.1 helper functions

/// wraps a chunk with a header returning the total length
///
/// helper function for ASN.1 encoding
fn asn_wrap(
    chunks: &mut [u8],
    header_f: impl Fn(&mut [u8], usize) -> Option<usize>,
    body_f: impl Fn(&mut [u8]) -> Option<usize>,
    body_len_f: impl Fn() -> Option<usize>,
) -> Option<usize> {
    let body_len = body_len_f()?;
    let header_len = calc_asn_header_len(body_len)?;

    let (head_chunk, body_chunk) = chunks.split_at_mut(header_len);

    let copied_body_len = body_f(body_chunk)?;
    let copied_header_len = header_f(head_chunk, body_len)?;

    debug_assert_eq!(copied_body_len, body_len);
    debug_assert_eq!(copied_header_len, header_len);

    let len = copied_header_len.checked_add(copied_body_len)?;
    Some(len)
}

/// writes a tag and the length encoded with a minimum number of octets
///
/// X.690 Section 10.1: DER lengths must be encoded with a minimum number of octets
///
/// helper function for ASN.1 encoding
fn write_asn_header(header: &mut [u8], tag: u8, len: usize) -> Option<usize> {
    let len: u32 = len.try_into().ok()?;

    match len.to_be_bytes() {
        [0, 0, 0, byte0] if byte0 < 0x80 => {
            header[0] = tag;
            header[1] = byte0;
            Some(2)
        }
        [0, 0, 0, byte0] => {
            header[0] = tag;
            header[1] = 0x81;
            header[2] = byte0;
            Some(3)
        }
        [0, 0, byte1, byte0] => {
            header[0] = tag;
            header[1] = 0x82;
            header[2] = byte1;
            header[3] = byte0;
            Some(4)
        }
        [0, byte2, byte1, byte0] => {
            header[0] = tag;
            header[1] = 0x83;
            header[2] = byte2;
            header[3] = byte1;
            header[4] = byte0;
            Some(5)
        }
        [byte3, byte2, byte1, byte0] => {
            header[0] = tag;
            header[1] = 0x84;
            header[2] = byte3;
            header[3] = byte2;
            header[4] = byte1;
            header[5] = byte0;
            Some(6)
        }
    }
}

/// size of header for a tag and the length encoded with a minimum number of octets
///
/// helper function for ASN.1 encoding
fn calc_asn_header_len(len: usize) -> Option<usize> {
    let len: u32 = len.try_into().ok()?;

    match len.to_be_bytes() {
        [0, 0, 0, byte] if byte < 0x80 => Some(2),
        [0, 0, 0, _] => Some(3),
        [0, 0, _, _] => Some(4),
        [0, _, _, _] => Some(5),
        [_, _, _, _] => Some(6),
    }
}

const ASN_SECTION_CONSTRUCTED: u8 = 0x30;
const ASN_OCTET_STRING: u8 = 0x04;

/// Naive ASN.1 encoding for OID 1.3.6.1.4.1.58270.1.3
pub fn asn1_encode_report_vcek(chunks: &mut [u8], report: &[u8], vcek: &[u8]) -> Option<usize> {
    let section_header =
        |header: &mut [u8], body_len| write_asn_header(header, ASN_SECTION_CONSTRUCTED, body_len);

    let octet_header =
        |header: &mut [u8], body_len| write_asn_header(header, ASN_OCTET_STRING, body_len);

    let report_chunk = |chunks: &mut [u8]| {
        // report data
        chunks[..report.len()].copy_from_slice(report);
        Some(report.len())
    };

    let report_chunk_len_f = || Some(report.len());

    let vcek_report = |chunks: &mut [u8]| {
        // vcek data
        let (vcek_chunk, chunks) = chunks.split_at_mut(vcek.len());
        vcek_chunk.copy_from_slice(vcek);
        let report_chunk_len = asn_wrap(chunks, octet_header, report_chunk, report_chunk_len_f)?;
        let len = report_chunk_len.checked_add(vcek.len())?;
        Some(len)
    };

    let vcek_report_len_f = || {
        let report_chunk_len = report_chunk_len_f()?;
        let vcek_len = vcek.len();
        let len = report_chunk_len
            .checked_add(calc_asn_header_len(report_chunk_len)?)?
            .checked_add(vcek_len)?;
        Some(len)
    };

    asn_wrap(chunks, section_header, vcek_report, vcek_report_len_f)
}
