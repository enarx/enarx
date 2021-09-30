// SPDX-License-Identifier: Apache-2.0

use std::io::{ErrorKind, Read, Result};
use wasmparser::{Chunk, Parser, Payload::*};

const RESOURCES_SECTION: &str = ".enarx.resources";

pub fn parse(
    mut input: impl Read,
    mut handle_custom: impl FnMut(&[u8]) -> Result<()>,
    mut handle_default: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut parser = Parser::new(0);
    let mut eof = false;
    let mut stack = Vec::new();

    loop {
        let (payload, consumed) = match parser.parse(&buf, eof).or(Err(ErrorKind::InvalidInput))? {
            Chunk::NeedMoreData(hint) => {
                assert!(!eof); // otherwise an error would be returned

                // Use the hint to preallocate more space, then read
                // some more data into our buffer.
                //
                // Note that the buffer management here is not ideal,
                // but it's compact enough to fit in an example!
                let len = buf.len();
                buf.extend((0..hint).map(|_| 0u8));
                let n = input.read(&mut buf[len..])?;
                buf.truncate(len + n);
                eof = n == 0;
                continue;
            }

            Chunk::Parsed { consumed, payload } => (payload, consumed),
        };

        match payload {
            CustomSection { name, data, .. } => {
                if name == RESOURCES_SECTION {
                    handle_custom(data)?;
                } else {
                    handle_default(&buf[..consumed])?;
                }
            }
            // When parsing nested modules we need to switch which
            // `Parser` we're using.
            ModuleSectionEntry {
                parser: subparser, ..
            } => {
                stack.push(parser);
                parser = subparser;
            }
            End => {
                if let Some(parent_parser) = stack.pop() {
                    parser = parent_parser;
                } else {
                    break;
                }
            }
            _ => {
                handle_default(&buf[..consumed])?;
            }
        }

        // once we're done processing the payload we can forget the
        // original.
        buf.drain(..consumed);
    }
    Ok(())
}
