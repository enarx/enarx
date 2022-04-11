# enarx-exec-wasmtime

`enarx-exec-wasmtime` - the Enarx WebAssembly loader

`enarx-exec-wasmtime` is responsible for loading and running WebAssembly modules
inside an Enarx keep.

Users generally won't execute `enarx-exec-wasmtime` directly, but for test/debugging
purposes it can be used to run a .wasm file with given command-line
arguments and environment variables.

### Example invocation

```console
$ wat2wasm ../tests/wasm/return_1.wat
$ RUST_LOG=enarx-exec-wasmtime=info RUST_BACKTRACE=1 cargo run -- return_1.wasm
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/x86_64-unknown-linux-musl/debug/enarx-exec-wasmtime return_1.wasm`
[INFO  enarx-exec-wasmtime] version 0.2.0 starting up
[WARN  enarx-exec-wasmtime] 🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭
[INFO  enarx-exec-wasmtime] opts: RunOptions {
        envs: [],
        module: Some(
            "return_1.wasm",
        ),
        args: [],
    }
[INFO  enarx-exec-wasmtime] reading module from "return_1.wasm"
[INFO  enarx-exec-wasmtime] running workload
[WARN  enarx-exec-wasmtime::workload] inheriting stdio from calling process
[INFO  enarx-exec-wasmtime] got result: Ok(
        [
            I32(
                1,
            ),
        ],
    )
```

If no filename is given, `enarx-exec-wasmtime` expects to read the WebAssembly module
from file descriptor 3, so this would be equivalent:
```console
$ RUST_LOG=enarx-exec-wasmtime=info RUST_BACKTRACE=1 cargo run -- 3< return_1.wasm
 ```


License: Apache-2.0
