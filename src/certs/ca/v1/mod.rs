mod decoders;
mod encoders;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Usage {
    AmdRootKey,
    AmdSevKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub key_id: u128,
    pub sig_id: u128,
    pub usage: Usage,
    pub pubexp: Vec<u8>,
    pub modulus: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub body: Body,
    pub signature: Vec<u8>,
}
