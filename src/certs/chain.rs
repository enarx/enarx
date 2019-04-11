use super::*;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    ca: ca::Chain,
    sev: sev::Chain,
}

impl codicon::Decoder for Chain {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        let sev = sev::Chain::decode(reader, ())?;
        let ca = ca::Chain::decode(reader, ())?;
        Ok(Self { ca, sev })
    }
}

impl codicon::Encoder for Chain {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        self.sev.encode(writer, ())?;
        self.ca.encode(writer, ())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for Chain {
    type Output = sev::Certificate;

    fn verify(self) -> Result<sev::Certificate> {
        let ask = self.ca.verify()?;
        (&ask, &self.sev.cek).verify()?;
        self.sev.verify()
    }
}
