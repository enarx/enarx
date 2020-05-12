// SPDX-License-Identifier: Apache-2.0

use std::fmt::Formatter;

/// Describes the range of errors one might encounter.
#[derive(Debug)]
pub enum Kind {
    /// Helpful for adding context messages around other errors.
    Context(String),
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Kind::Context(msg) => std::fmt::Display::fmt(&msg, f),
        }
    }
}

/// Quickly construct a Context Error.
#[macro_export]
macro_rules! context {
    ($msg:expr, $err:expr) => {
        crate::error::Error::context($msg, std::boxed::Box::new($err))
    };
}

/// The primary error type for the crate.
#[derive(Debug)]
pub struct Error {
    pub kind: Kind,
    pub cause: Option<Box<dyn std::error::Error + 'static>>,
}

impl Error {
    /// Enclose another error with a helpful human-readable message.
    pub fn context(msg: String, cause: Box<dyn std::error::Error + 'static>) -> Self {
        Self {
            kind: Kind::Context(msg),
            cause: Some(cause),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use std::error::Error as _;

        std::fmt::Display::fmt(&self.kind, f)?;

        if let Some(e) = self.source() {
            std::fmt::Display::fmt("\nCaused by:\n", f)?;
            std::fmt::Display::fmt(&e, f)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}
