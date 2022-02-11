// SPDX-License-Identifier: Apache-2.0

use crate::uarch::{Report, ReportData, TargetInfo};

use sallyport::request;
use sallyport::syscall::{
    BaseSyscallHandler, EnarxSyscallHandler, SGX_QUOTE_SIZE, SGX_TECH, SYS_ENARX_GETATT,
};
use sallyport::untrusted::{UntrustedRef, UntrustedRefMut, ValidateSlice};

impl<'a> EnarxSyscallHandler for super::Handler<'a> {
    // NOTE: The 'nonce' field is called 'hash' here, as it is used to pass in
    // a hash of a public key from the client that is to be embedded in the Quote.
    // For more on this syscall, see: https://github.com/enarx/enarx/issues/966
    fn get_attestation(
        &mut self,
        hash: UntrustedRef<'_, u8>,
        hash_len: libc::size_t,
        buf: UntrustedRefMut<'_, u8>,
        buf_len: libc::size_t,
    ) -> sallyport::Result {
        self.trace("get_attestation", 0);

        // If hash is NULL ptr, it is a Quote size request; return expected Quote size
        // without proxying to host. Otherwise get hash value.
        let hash = match hash.validate_slice(hash_len, self) {
            None => {
                let rep: sallyport::Reply = Ok([SGX_QUOTE_SIZE.into(), SGX_TECH.into()]).into();
                return sallyport::Result::from(rep);
            }
            Some(h) => {
                if h.len() != 64 {
                    return Err(libc::EINVAL);
                }
                let mut hash = [0u8; 64];
                hash.copy_from_slice(h);
                hash
            }
        };

        // Used internally for buffer size to host when getting TargetInfo
        const REPORT_LEN: usize = 512;

        // Validate output buf memory
        let buf = buf.validate_slice(buf_len, self).ok_or(libc::EFAULT)?;

        // Request TargetInfo from host by passing nonce as 0
        let c = self.new_cursor();
        let (_, shim_buf_ptr) = c.alloc::<u8>(buf_len).or(Err(libc::EMSGSIZE))?;
        let req = request!(SYS_ENARX_GETATT => 0, 0, shim_buf_ptr.as_ptr(), REPORT_LEN);
        unsafe { self.proxy(req)? };

        // Retrieve TargetInfo from sallyport block and call EREPORT to
        // create Report from TargetInfo.
        let mut ti_buf = [0u8; 512];
        let ti_len = ti_buf.len();
        let c = self.new_cursor();

        unsafe {
            c.copy_into_slice(buf_len, &mut ti_buf[..ti_len])
                .or(Err(libc::EFAULT))?;
        }

        // Generate Report
        let mut target_info: TargetInfo = Default::default();
        let mut f = [0u8; 8];
        let mut x = [0u8; 8];
        f.copy_from_slice(&ti_buf[32..40]);
        x.copy_from_slice(&ti_buf[40..48]);
        let f = u64::from_le_bytes(f);
        let x = u64::from_le_bytes(x);
        target_info.mrenclave.copy_from_slice(&ti_buf[0..32]);
        target_info.attributes = [f, x];

        let report: Report = target_info.enclu_ereport(&ReportData(hash));

        // Request Quote from host
        let report_slice = &[report];
        let report_bytes = unsafe {
            core::slice::from_raw_parts(
                report_slice.as_ptr() as *const _ as *const u8,
                core::mem::size_of::<Report>(),
            )
        };

        let c = self.new_cursor();
        let (c, shim_nonce_ptr) = c.copy_from_slice(report_bytes).or(Err(libc::EMSGSIZE))?;
        let (_, shim_buf_ptr) = c.alloc::<u8>(buf_len).or(Err(libc::EMSGSIZE))?;
        let req = request!(SYS_ENARX_GETATT => shim_nonce_ptr.as_ptr(), report_bytes.len(), shim_buf_ptr.as_ptr(), buf_len);
        let result = unsafe { self.proxy(req)? };

        // Pass Quote back to code layer in buf
        let c = self.new_cursor();
        let (c, _) = c.alloc::<u8>(report_bytes.len()).or(Err(libc::EMSGSIZE))?;

        let result_len: usize = result[0].into();
        if result_len > buf_len {
            self.attacked()
        }

        unsafe {
            c.copy_into_slice(buf_len, &mut buf[..result_len])
                .or(Err(libc::EFAULT))?
        };

        let rep: sallyport::Reply = Ok([SGX_QUOTE_SIZE.into(), SGX_TECH.into()]).into();
        sallyport::Result::from(rep)
    }
}
