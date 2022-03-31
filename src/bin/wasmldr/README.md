# wasmldr

`wasmldr` - the Enarx WebAssembly loader

`wasmldr` is responsible for loading and running WebAssembly modules
inside an Enarx keep.

Users generally won't execute `wasmldr` directly, but for test/debugging
purposes it can be used to run a .wasm file with given command-line
arguments and environment variables.

### Example invocation

```console
$ wat2wasm ../tests/wasm/return_1.wat
$ RUST_LOG=wasmldr=info RUST_BACKTRACE=1 cargo run -- return_1.wasm
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/x86_64-unknown-linux-musl/debug/wasmldr return_1.wasm`
[INFO  wasmldr] version 0.2.0 starting up
[WARN  wasmldr] 🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭
[INFO  wasmldr] opts: RunOptions {
        envs: [],
        module: Some(
            "return_1.wasm",
        ),
        args: [],
    }
[INFO  wasmldr] reading module from "return_1.wasm"
[INFO  wasmldr] running workload
[WARN  wasmldr::workload] inheriting stdio from calling process
[INFO  wasmldr] got result: Ok(
        [
            I32(
                1,
            ),
        ],
    )
```

If no filename is given, `wasmldr` expects to read the WebAssembly module
from file descriptor 3, so this would be equivalent:
```console
$ RUST_LOG=wasmldr=info RUST_BACKTRACE=1 cargo run -- 3< return_1.wasm
 ```


License: Apache-2.0
