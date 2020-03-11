// SPDX-License-Identifier: Apache-2.0

//! The `code` module contains convenient symbolic descriptions
//! of the possible commands that may be made to the SEV platform.
//!
//! Chapter 4.3, "Command Identifiers"

enumerate::enumerate! {
    /// Symbolic representation of the command codes exported by the
    /// SEV API. These enums map directly to an integral value that the
    /// SEV API calls an "ID."
    #[derive(Copy, Clone)]
    pub enum Code: u32 {
        /// Initialize the platform.
        Init = 0x001,

        /// Initialize the platform with extended parameters.
        InitEx = 0x00d,

        /// Shut the platform down.
        Shutdown = 0x002,

        /// Delete the persistent platform state.
        PlatformReset = 0x003,

        /// Query the platform status.
        PlatformStatus = 0x004,

        /// Generate a new PEK.
        PekGen = 0x005,

        /// Generate a PEK certificate signing request.
        PekCsr = 0x006,

        /// Import the signed PEK certificate.
        PekCertImport = 0x007,

        /// Export the PDH and its certificate chain.
        PdhCertExport = 0x008,

        ///Generate a new PDH and PEK signature.
        PdhGen = 0x009,

        /// Download new SEV firmware.
        DownloadFirmware = 0x00b,

        /// Get the system's unique ID.
        GetId = 0x00c,

        /// Begin the launch process for a new SEV-enabled
        /// guest.
        LaunchStart = 0x030,

        /// Encrypt guest data for launch.
        LaunchUpdateData = 0x031,

        /// Encrypt guest VMCB save area for launch (SEV-ES).
        LaunchUpdateVmsa = 0x032,

        /// Produce a measurement of the guest launch.
        LaunchMeasure = 0x033,

        /// Import a guest secret from the guest owner.
        LaunchUpdateSecret = 0x034,

        /// Complete the guest launch workflow.
        LaunchFinish = 0x035,

        /// Begin to send a guest to a new remote platform.
        SendStart = 0x040,

        /// Re-encrypt guest data for transmission.
        SendUpdateData = 0x041,

        /// Re-encrypt guest VMCB save area for transmission (SEV-ES).
        SendUpdateVmsa = 0x042,

        /// Complete sending the guest to the remote platform.
        SendFinish = 0x043,

        /// Begin to receive guest data from a remote platform.
        ReceiveStart = 0x050,

        /// Re-encrypt guest data from transmission.
        ReceiveUpdateData = 0x051,

        /// Re-encrypt guest VMCB save area from transmission (SEV-ES).
        ReceiveUpdateVmsa = 0x052,

        /// Complete guest import from remote platform.
        ReceiveFinish = 0x053,

        /// Query the status and metadata of a guest.
        GuestStatus = 0x023,

        /// Load a guest's key into the memory controller.
        Activate = 0x021,

        /// Unload a guest's key from the memory controller.
        Deactivate = 0x022,

        /// Copy encrypted guest memory into a new guest location.
        Copy = 0x024,

        /// Load a guest's key into the memory controller.
        ActivateEx = 0x025,

        /// Flush the data fabric.
        DfFlush = 0x00a,

        /// Delete the guest's SEV context managed by the platform.
        Decommission = 0x020,

        /// Decrypt guest memory region for debugging.
        DbgDecrypt = 0x060,

        /// Encrypt guest memory region for debugging.
        DbgEncrypt = 0x061,
    }
}
