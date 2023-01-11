This crate provides `Config`, which can be used to with any `serde` deserializer.
Its main purpose is to read an `Enarx.toml` configuration file.

```rust
extern crate toml;
use enarx_config::Config;
const CONFIG: &str = r#"
[network.incoming.12345]
prot = "tls"
"#;

let config: Config = toml::from_str(CONFIG).unwrap();
```
