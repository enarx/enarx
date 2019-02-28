mod decoders;
mod encoders;

#[cfg(test)]
mod naples;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Usage {
    AmdRootKey,
    AmdSevKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Body1 {
    pub(crate) key_id: u128,
    pub(crate) sig_id: u128,
    pub(crate) usage: Usage,
    pub(crate) pubexp: Vec<u8>,
    pub(crate) modulus: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Versioned {
    Version1(Body1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate(pub(crate) Versioned);
