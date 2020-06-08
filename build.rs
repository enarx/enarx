// Let people using the standard `cargo x` syntax 
fn main() {
    
    panic!("
    
    Enarx uses `cargo-make` to build and run its code:
    https://github.com/sagiegurari/cargo-make

    To build Enarx:

    1. Install cargo-make.
    $ cargo install cargo-make

    2. Build Enarx.
    $ cargo make build

    3. You can optionally run tests.
    $ cargo make test

    For more information, see:
    https://github.com/enarx/enarx/wiki/How-to-contribute-code#enarx-development-environment-set-up
    
    ");
}
