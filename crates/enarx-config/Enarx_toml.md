# Configure Enarx.toml

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
steward = "https://attest.profian.com"
```

### `stdin`, `stdout` and `stderr`

#### `kind`

`kind` can be either `"null"` or `"host"`.

### `network`

#### `network.incoming`

`network.incoming` defines incoming network connection policy.

Keys are listening port numbers.

A special `default` key defines default network policy to be used for incoming network connections if no matching entry is present.

##### `prot`

`prot` can be `"tcp"` or `"tls"`

`tls` transparently wraps a TCP connection with the TLS protocol.

#### Example

```toml
[network.incoming.default]
prot = "tcp"

[network.incoming.9000]
prot = "tls"

[network.incoming.9001]
prot = "tcp"
```

#### `network.outgoing`

`network.outgoing` defines outgoing network connection policy.

Keys are Ipv4, Ipv6 or domain name hosts with optional port.

If a host is specified without a port and one or more entries exist for the same host with a port, then the policy with a port takes precedence for connections using that port. For example, if `network.outgoing."example.com"` and `network.outgoing."example.com:12345"` both exist, then `network.outgoing."example.com:12345"` policy would be used for connections to `example.com` on port `12345` and policy for `example.com` would be used for all other connections.

Host specification must match the URL standard as defined at https://url.spec.whatwg.org/#hosts-(domains-and-ip-addresses)

A special `default` key defines default network policy to be used for outgoing network connections if no matching entry is present.

##### `prot`

`prot` can be `"tcp"` or `"tls"`

`tls` transparently wraps a TCP connection with the TLS protocol.

```toml
[network.outgoing.default]
prot = "tcp"

[network.outgoing."tls.example.com"]
prot = "tls"

[network.outgoing."tls.example.com:8080"]
prot = "tcp"

[network.outgoing."tcp.example.com"]
prot = "tcp"

[network.outgoing."1.2.3.4:8080"]
prot = "tls"

[network.outgoing."1.2.3.4"]
prot = "tcp"

[network.outgoing."[2001:db8::1:0:0:1]"]
prot = "tcp"

[network.outgoing."[2001:db8::1:0:0:1]:5000"]
prot = "tls"
```

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

# Standard I/O configuration
[stdin]
kind = "null"

[stdout]
kind = "host"

[stderr]
kind = "host"

# An incoming network policy for connections on port 12345
[networking.incoming.12345]
prot = "tls" # or prot = "tcp"

# An incoming network policy for connections to "127.0.0.1:23456"
[networking.outgoing."127.0.0.1:23456"]
prot = "tcp" # or prot = "tls"
```

This configuration files passes the environment `VAR1=var1 VAR2=var2` and the arguments `--argument1 --argument2=foo` to the WASM application.

Additionally, three file descriptors are pre-opened:
- 0: `/dev/null`
- 1: `/dev/stdout`
- 2: `/dev/stderr`
