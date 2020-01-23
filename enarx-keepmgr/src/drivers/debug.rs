// SPDX-License-Identifier: Apache-2.0

use super::*;

pub struct Debug<T: AsRef<Path>>(T);

impl<T: AsRef<Path>> Debug<T> {
    pub fn new(shim: T) -> Self {
        Self(shim)
    }
}

impl<T: AsRef<Path>> Driver for Debug<T> {
    fn name(&self) -> &str {
        "debug"
    }

    fn shim(&self) -> Result<&Path> {
        Ok(self.0.as_ref())
    }

    fn make(&self) -> Result<ShimSetup> {
        Ok(Box::new(Synthetic))
    }
}

struct Synthetic;

impl Loader<KeepSetup> for Synthetic {
    fn load(&mut self, src: &[u8], dst: Span<u64>, access: Access) -> Result<()> {
        eprintln!("setup: shim: {:08x} {:?} {:?}", src.len(), dst, access);
        Ok(())
    }

    fn done(self: Box<Self>, entry: u64) -> Result<KeepSetup> {
        eprintln!("setup: shim: {:016x}", entry);
        Ok(self)
    }
}

impl Loader<ShimBuild> for Synthetic {
    fn load(&mut self, src: &[u8], dst: Span<u64>, access: Access) -> Result<()> {
        eprintln!("setup: keep: {:08x} {:?} {:?}", src.len(), dst, access);
        Ok(())
    }

    fn done(self: Box<Self>, entry: u64) -> Result<ShimBuild> {
        eprintln!("setup: keep: {:016x}", entry);
        Ok(self)
    }
}

impl Loader<KeepBuild> for Synthetic {
    fn load(&mut self, src: &[u8], dst: Span<u64>, access: Access) -> Result<()> {
        eprintln!("build: shim: {:08x} {:?} {:?}", src.len(), dst, access);
        Ok(())
    }

    fn done(self: Box<Self>, entry: u64) -> Result<KeepBuild> {
        eprintln!("build: shim: {:016x}", entry);
        Ok(self)
    }
}

impl Loader<Keep<()>> for Synthetic {
    fn load(&mut self, src: &[u8], dst: Span<u64>, access: Access) -> Result<()> {
        eprintln!("build: keep: {:08x} {:?} {:?}", src.len(), dst, access);
        Ok(())
    }

    fn done(self: Box<Self>, entry: u64) -> Result<Keep<()>> {
        eprintln!("build: keep: {:016x}", entry);
        Ok(self)
    }
}

impl Enterer<()> for Synthetic {
    fn enter(self: Box<Self>, _: ()) -> Result<Event> {
        Ok(Event::getuid(self))
    }
}

impl Enterer<libc::uid_t> for Synthetic {
    fn enter(self: Box<Self>, uid: libc::uid_t) -> Result<Event> {
        eprintln!("uid: {}", uid);
        Ok(Event::exit(0))
    }
}
