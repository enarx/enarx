use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

fn main() -> io::Result<()> {
    let listener = UnixListener::bind("/tmp/enarx_unix_echo_to_bin")?;
    let (mut socket, _) = listener.accept()?;

    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer)?;

    let mut socket = UnixStream::connect("/tmp/enarx_unix_echo_from_bin").unwrap();
    socket.write_all(&buffer)?;
    Ok(())
}
