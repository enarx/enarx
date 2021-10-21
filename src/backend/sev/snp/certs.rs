// SPDX-License-Identifier: Apache-2.0

use super::firmware::{Identifier, TcbVersion};

pub const CHAIN_URL: &str = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain";

pub fn vcek_url(id: Identifier, version: TcbVersion) -> String {
    format!(
        "https://kdsintf.amd.com/vcek/v1/Milan/{:x}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        id,
        version.bootloader,
        version.tee,
        version.snp,
        version.microcode,
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vcek_url() {
        assert_eq!(vcek_url(vec![
                0x8b, 0xa8, 0x26, 0xb2, 0xdd, 0x6a, 0xb6, 0x5e,
                0x40, 0x1e, 0x0c, 0x4d, 0x41, 0x28, 0xef, 0x4b,
                0x43, 0x4e, 0xd0, 0xcc, 0xb2, 0x13, 0xf6, 0x6c,
                0x5f, 0x57, 0x7b, 0x51, 0x87, 0x30, 0xef, 0x58,
                0x92, 0xf7, 0x8a, 0x78, 0xbe, 0x25, 0x99, 0x76,
                0x97, 0x31, 0x25, 0xa3, 0xb9, 0xb3, 0xd1, 0x9f,
                0x28, 0x6c, 0x91, 0x2c, 0xf5, 0x77, 0x6f, 0xdf,
                0xce, 0xe5, 0x26, 0x0f, 0xa4, 0x57, 0x6c, 0x4b,
        ].into(),
            TcbVersion {
                bootloader: 0,
                tee: 0,
                snp: 3,
                microcode: 29,
                ..Default::default()
            },
        ), "https://kdsintf.amd.com/vcek/v1/Milan/8ba826b2dd6ab65e401e0c4d4128ef4b434ed0ccb213f66c5f577b518730ef5892f78a78be259976973125a3b9b3d19f286c912cf5776fdfcee5260fa4576c4b?blSPL=00&teeSPL=00&snpSPL=03&ucodeSPL=29");
    }
}
