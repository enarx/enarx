mod decoders;
mod encoders;
pub mod v1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Certificate {
    Version1(v1::Certificate)
}
