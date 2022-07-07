# The Enarx.toml configuration file

With the `Enarx.toml` configuration file, environment variables, arguments and pre-opened file descriptors
can be passed to the WASM application.

## Elements

All elements are optional.

### `env`

`env` specifies the environment variables exported to the WASM application in a map.

#### Example

```toml
[env]
VAR1 = "var1"
VAR2 = "var2"
```

### `args`

`args` specifies the arguments for the WASM application in an array.

#### Example

```toml
args = [
     "--argument1",
     "--argument2=foo"
]
```

### `steward`

`steward` specifies the URL for the steward to contact for a TLS certificate.

#### Example

```toml
steward = "https://steward.example.com"
```

### `files`

`files` specifies an array of file descriptor definitions to be pre-opened for the WASM application.

A `files` entry can contain the following sub elements.

#### `kind`

`kind` can be one of `"null"`, `"stdin"`,`"stdout"`, `"stderr"`, `"listen"` or `"connect"`.

#### `name`

Name of the file descriptor, exported in the `FD_NAMES` environment variable.
The default `name` for `kind`  `"null"`, `"stdin"`,`"stdout"`, `"stderr"` is the `kind`. 

The `FD_NAMES` environment variable contains all `name` strings of the `files` array joined with ":".
The `FD_COUNT` environment variable contains the number of `files` elements.

#### `prot`

`prot` can be `"tcp"` or `"tls"` for `kind = "connect"` or `kind = "listen"`.

`"tls"` is the default, if `prot` is not specified.

`tls` transparently wraps a TCP connection with the TLS protocol.
For `kind = "listen"` every accepted connection is also wrapped with the TLS protocol. 

#### `host`

`host` specifies the host to connect to for a `kind = "connect"`

#### `addr`

`addr` specifies the address to bind to for a `kind = "listen"`.

##### Examples

```toml
addr = "::"          # bind to any interface IPv6 and IPv4 (the default, if not specified)
addr = "0.0.0.0"     # bind to any IPv4 interface
addr = "::1"         # bind to IPv6 localhost
addr = "127.0.0.1"   # bind to IPv4 localhost
addr = "192.168.1.1" # bind to a specific IPv4 address
```

#### `port`

`port` specifies the port to connect or bind to for `kind = "connect"` or `kind = "listen"`.
The default value is `443`.

## Example
```toml
# Configuration for a WASI application in an Enarx Keep

# Arguments
args = [
     "--argument1",
     "--argument2=foo"
]

# Environment variables
[env]
VAR1 = "var1"
VAR2 = "var2"

# Pre-opened file descriptors
[[files]]
kind = "null"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

# A listen socket
[[files]]
name = "LISTEN"
kind = "listen"
prot = "tls" # or prot = "tcp"
port = 12345

# An outgoing connected socket
[[files]]
name = "CONNECT"
kind = "connect"
prot = "tcp" # or prot = "tls"
host = "127.0.0.1"
port = 23456
```

This configuration files passes the environment `VAR1=var1 VAR2=var2` and the arguments `--argument1 --argument2=foo` to the WASM application.

Additionally, five file descriptors are pre-opened:
- 0: `/dev/null`
- 1: `/dev/stdout`
- 2: `/dev/stderr`
- 3: a TCP listen socket bound to port `12345` on address `::`, where every accepted connection is transparently wrapped with the TLS protocol 
- 4: a normal TCP stream socket connected to `127.0.0.1:23456`

Additionally, the following environment variables are exported:
- `FD_COUNT=5`
- `FD_NAMES=null:stdout:stderr:LISTEN:CONNECT`
