mod ark;
mod ask;
mod cek;
mod oca;
mod pek;
mod pdh;

const OCA: &[u8] = include_bytes!("oca.cert");
const ARK: &[u8] = include_bytes!("ark.cert");
const ASK: &[u8] = include_bytes!("ask.cert");
const CEK_SIG: &[u8] = include_bytes!("cek.sig.cert");
const CEK_UNS: &[u8] = include_bytes!("cek.uns.cert");
const PEK: &[u8] = include_bytes!("pek.cert");
const PDH: &[u8] = include_bytes!("pdh.cert");

const CA_SIG_OFFSET: usize = 0x40 + 2048 / 8 + 2048 / 8;
const SEV_SIG_OFFSET: usize = 0x414;
