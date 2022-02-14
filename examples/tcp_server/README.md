# MIO TCP Echo Server Example 

This example is an adapted version of the upstream `mio` crate `tcp_server` example.

It currently depends on a modified version of `mio` with support for WASI.

The added part creates the `TcpListener` from file descriptor `3`,
if the `LISTEN_FDS` environment variable is set.


## How to run this example

### Install `enarx`

Either from `crates.io` or from this git repository:

```
$ cd <enarx_repo>
$ cargo install --path . 
```

### Build the WASM application

```
$ cargo build --target wasm32-wasi -p tcp_server
[…]
    Finished dev [unoptimized + debuginfo] target(s) in 1.44s
```

### Run it

```
$ enarx run --wasmcfgfile examples/tcp_server/Enarx.toml target/wasm32-wasi/debug/tcp_server.wasm 
[WARN  wasmldr] 🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭
[DEBUG wasmldr] parsing argv
[INFO  wasmldr] opts: RunOptions {
        module: None,
        config: None,
    }
[INFO  wasmldr] reading module from fd 3
[INFO  wasmldr] reading config from fd 4
[INFO  wasmldr] running workload
[DEBUG wasmldr::workload] configuring wasmtime engine
[DEBUG wasmldr::workload] instantiating wasmtime linker
[DEBUG wasmldr::workload] adding WASI to linker
[DEBUG wasmldr::workload] creating WASI context
[DEBUG wasmldr::workload] Processing loader config Config {
        files: Some(
            [
                File {
                    type_: "stdio",
                    name: "stdin",
                    addr: None,
                    port: None,
                },
                File {
                    type_: "stdio",
                    name: "stdout",
                    addr: None,
                    port: None,
                },
                File {
                    type_: "stdio",
                    name: "stderr",
                    addr: None,
                    port: None,
                },
                File {
                    type_: "tcp_listen",
                    name: "TEST_TCP_LISTEN",
                    addr: None,
                    port: Some(
                        9000,
                    ),
                },
            ],
        ),
    }
[DEBUG wasmldr::workload] creating wasmtime Store
[DEBUG wasmldr::workload] instantiating module from bytes
[DEBUG wasmldr::workload] adding module to store
[DEBUG wasmldr::workload] getting module's default function
[DEBUG wasmldr::workload] calling function
Using preopened socket FD 3
You can connect to the server using `nc`:
 $ nc <IP> <PORT>
You'll see our welcome message and anything you type will be printed here.

```

Then from another shell:
```
$ echo ECHO | ncat 127.0.0.1 9000
Hello world!
ECHO
```

or, if you don't have `ncat`:
```
$ echo ECHO | netcat -q 1 127.0.0.1 9000
Hello world!
ECHO
```

and see the output of the Enarx keep:
```
Accepted connection from: 0.0.0.0:0
Received data: ECHO
Connection closed
```

To modify the port and listen address see the `Enarx.toml` file in the
example directory.
