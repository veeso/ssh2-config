# ssh2-config

<p align="center">
  <a href="CHANGELOG.md" target="_blank">Changelog</a>
  ·
  <a href="#get-started" target="_blank">Get started</a>
  ·
  <a href="https://docs.rs/ssh2-config" target="_blank">Documentation</a>
</p>

<p align="center">Developed by <a href="https://veeso.github.io/" target="_blank">@veeso</a></p>
<p align="center">Current version: 0.4.0 (15/03/2025)</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"
    ><img
      src="https://img.shields.io/badge/License-MIT-teal.svg"
      alt="License-MIT"
  /></a>
  <a href="https://github.com/veeso/ssh2-config/stargazers"
    ><img
      src="https://img.shields.io/github/stars/veeso/ssh2-config.svg"
      alt="Repo stars"
  /></a>
  <a href="https://crates.io/crates/ssh2-config"
    ><img
      src="https://img.shields.io/crates/d/ssh2-config.svg"
      alt="Downloads counter"
  /></a>
  <a href="https://crates.io/crates/ssh2-config"
    ><img
      src="https://img.shields.io/crates/v/ssh2-config.svg"
      alt="Latest version"
  /></a>
  <a href="https://ko-fi.com/veeso">
    <img
      src="https://img.shields.io/badge/donate-ko--fi-red"
      alt="Ko-fi"
  /></a>
</p>
<p align="center">
  <a href="https://github.com/veeso/ssh2-config/actions"
    ><img
      src="https://github.com/veeso/ssh2-config/workflows/Build/badge.svg"
      alt="Build"
  /></a>
  <a href="https://coveralls.io/github/veeso/ssh2-config"
    ><img
      src="https://coveralls.io/repos/github/veeso/ssh2-config/badge.svg"
      alt="Coveralls"
  /></a>
  <a href="https://docs.rs/ssh2-config"
    ><img
      src="https://docs.rs/ssh2-config/badge.svg"
      alt="Docs"
  /></a>
</p>

---

- [ssh2-config](#ssh2-config)
  - [About ssh2-config](#about-ssh2-config)
    - [Exposed attributes](#exposed-attributes)
    - [Missing features](#missing-features)
  - [Get started 🚀](#get-started-)
    - [Reading unsupported fields](#reading-unsupported-fields)
    - [Examples](#examples)
  - [Support the developer ☕](#support-the-developer-)
  - [Contributing and issues 🤝🏻](#contributing-and-issues-)
  - [Changelog ⏳](#changelog-)
  - [License 📃](#license-)

---

## About ssh2-config

ssh2-config a library which provides a parser for the SSH configuration file, to be used in pair with the [ssh2](https://github.com/alexcrichton/ssh2-rs) crate.

This library provides a method to parse the configuration file and returns the configuration parsed into a structure.
The `SshConfig` structure provides all the attributes which **can** be used to configure the **ssh2 Session** and to resolve
the host, port and username.

Once the configuration has been parsed you can use the `query(&str)` method to query configuration for a certain host, based on the configured patterns.

Even if many attributes are not exposed, since not supported, there is anyway a validation of the configuration, so invalid configuration will result in a parsing error.

### Exposed attributes

- **BindAddress**: you can use this attribute to bind the socket to a certain address
- **BindInterface**: you can use this attribute to bind the socket to a certain network interface
- **CASignatureAlgorithms**: you can use this attribute to handle CA certificates
- **CertificateFile**: you can use this attribute to parse the certificate file in case is necessary
- **Ciphers**: you can use this attribute to set preferred methods with the session method `session.method_pref(MethodType::CryptCs, ...)` and `session.method_pref(MethodType::CryptSc, ...)`
- **Compression**: you can use this attribute to set whether compression is enabled with `session.set_compress(value)`
- **ConnectionAttempts**: you can use this attribute to cycle over connect in order to retry
- **ConnectTimeout**: you can use this attribute to set the connection timeout for the socket
- **HostName**: you can use this attribute to get the real name of the host to connect to
- **IdentityFile**: you can use this attribute to set the keys to try when connecting to remote host.
- **KexAlgorithms**: you can use this attribute to configure Key exchange methods with `session.method_pref(MethodType::Kex, algos.join(",").as_str())`
- **MACs**: you can use this attribute to configure the MAC algos with `session.method_pref(MethodType::MacCs, algos.join(",").as_str())` and `session.method_pref(MethodType::MacSc, algos.join(",").as_str())`
- **Port**: you can use this attribute to resolve the port to connect to
- **PubkeyAuthentication**: you can use this attribute to set whether to use the pubkey authentication
- **RemoteForward**: you can use this method to implement port forwarding with `session.channel_forward_listen()`
- **ServerAliveInterval**: you can use this method to implement keep alive message interval
- **TcpKeepAlive**: you can use this method to tell whether to send keep alive message
- **UseKeychain**: (macos only) used to tell whether to use keychain to decrypt ssh keys
- **User**: you can use this method to resolve the user to use to log in as

### Missing features

- [Match patterns](http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Match) (Host patterns are supported!!!)
- [Tokens](http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#TOKENS)

---

## Get started 🚀

First of all, add ssh2-config to your dependencies

```toml
[dependencies]
ssh2-config = "^0.4"
```

then parse the configuration

```rust
use ssh2_config::{ParseRule, SshConfig};
use std::fs::File;
use std::io::BufReader;

let mut reader = BufReader::new(File::open(config_path).expect("Could not open configuration file"));
let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT).expect("Failed to parse configuration");

// Query attributes for a certain host
let params = config.query("192.168.1.2");
```

then you can use the parsed parameters to configure the session:

```rust
use ssh2::Session;
use ssh2_config::{HostParams};

fn configure_session(session: &mut Session, params: &HostParams) {
    if let Some(compress) = params.compression {
        session.set_compress(compress);
    }
    if params.tcp_keep_alive.unwrap_or(false) && params.server_alive_interval.is_some() {
        let interval = params.server_alive_interval.unwrap().as_secs() as u32;
        session.set_keepalive(true, interval);
    }
    // algos
    if let Some(algos) = params.kex_algorithms.as_deref() {
        if let Err(err) = session.method_pref(MethodType::Kex, algos.join(",").as_str()) {
            panic!("Could not set KEX algorithms: {}", err);
        }
    }
    if let Some(algos) = params.host_key_algorithms.as_deref() {
        if let Err(err) = session.method_pref(MethodType::HostKey, algos.join(",").as_str()) {
            panic!("Could not set host key algorithms: {}", err);
        }
    }
    if let Some(algos) = params.ciphers.as_deref() {
        if let Err(err) = session.method_pref(MethodType::CryptCs, algos.join(",").as_str()) {
            panic!("Could not set crypt algorithms (client-server): {}", err);
        }
        if let Err(err) = session.method_pref(MethodType::CryptSc, algos.join(",").as_str()) {
            panic!("Could not set crypt algorithms (server-client): {}", err);
        }
    }
    if let Some(algos) = params.mac.as_deref() {
        if let Err(err) = session.method_pref(MethodType::MacCs, algos.join(",").as_str()) {
            panic!("Could not set MAC algorithms (client-server): {}", err);
        }
        if let Err(err) = session.method_pref(MethodType::MacSc, algos.join(",").as_str()) {
            panic!("Could not set MAC algorithms (server-client): {}", err);
        }
    }
}

fn auth_with_rsakey(
    session: &mut Session,
    params: &HostParams,
    username: &str,
    password: Option<&str>
) {
    for identity_file in params.identity_file.unwrap_or_default().iter() {
        if let Ok(_) = session.userauth_pubkey_file(username, None, identity_file, password) {
            break;
        } 
    }
}

```

### Reading unsupported fields

As outlined above, ssh2-config does not support all parameters available in the man page of the SSH configuration file.

If you require these fields you may still access them through the `unsupported_fields` field on the `HostParams` structure like this:

```rust
use ssh2_config::{ParseRule, SshConfig};
use std::fs::File;
use std::io::BufReader;

let mut reader = BufReader::new(File::open(config_path).expect("Could not open configuration file"));
let config = SshConfig::default().parse(&mut reader, ParseRule::ALLOW_UNSUPPORTED_FIELDS).expect("Failed to parse configuration");

// Query attributes for a certain host
let params = config.query("192.168.1.2");
let forwards = params.unsupported_fields.get("dynamicforward");
```

### Examples

You can view a working examples of an implementation of ssh2-config with ssh2 in the examples folder at [client.rs](examples/client.rs).

You can run the example with

```sh
cargo run --example client -- <remote-host> [config-file-path]
```

---

## Support the developer ☕

If you like ssh2-config and you're grateful for the work I've done, please consider a little donation 🥳

You can make a donation with one of these platforms:

[![ko-fi](https://img.shields.io/badge/Ko--fi-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/veeso)
[![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/chrisintin)

---

## Contributing and issues 🤝🏻

Contributions, bug reports, new features and questions are welcome! 😉
If you have any question or concern, or you want to suggest a new feature, or you want just want to improve ssh2-config, feel free to open an issue or a PR.

Please follow [our contributing guidelines](CONTRIBUTING.md)

---

## Changelog ⏳

View ssh2-config's changelog [HERE](CHANGELOG.md)

---

## License 📃

ssh2-config is licensed under the MIT license.

You can read the entire license [HERE](LICENSE)
