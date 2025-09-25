# ssh2-config

<p align="center">
  <a href="CHANGELOG.md" target="_blank">Changelog</a>
  ·
  <a href="#get-started" target="_blank">Get started</a>
  ·
  <a href="https://docs.rs/ssh2-config" target="_blank">Documentation</a>
</p>

<p align="center">Developed by <a href="https://veeso.github.io/" target="_blank">@veeso</a></p>
<p align="center">Current version: 0.6.2 (25/09/2025)</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"
    ><img
      src="https://img.shields.io/badge/License-MIT-teal.svg"
      alt="License-MIT"
  /></a>
  <a href="https://github.com/veeso/ssh2-config/stargazers"
    ><img
      src="https://img.shields.io/github/stars/veeso/ssh2-config.svg?style=flat&logo=github"
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
  - [How host parameters are resolved](#how-host-parameters-are-resolved)
    - [Resolvers examples](#resolvers-examples)
  - [Configuring default algorithms](#configuring-default-algorithms)
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

- **AddKeysToAgent**: you can use this attribute add keys to the SSH agent
- **BindAddress**: you can use this attribute to bind the socket to a certain address
- **BindInterface**: you can use this attribute to bind the socket to a certain network interface
- **CASignatureAlgorithms**: you can use this attribute to handle CA certificates
- **CertificateFile**: you can use this attribute to parse the certificate file in case is necessary
- **Ciphers**: you can use this attribute to set preferred methods with the session method `session.method_pref(MethodType::CryptCs, ...)` and `session.method_pref(MethodType::CryptSc, ...)`
- **Compression**: you can use this attribute to set whether compression is enabled with `session.set_compress(value)`
- **ConnectionAttempts**: you can use this attribute to cycle over connect in order to retry
- **ConnectTimeout**: you can use this attribute to set the connection timeout for the socket
- **ForwardAgent**: you can use this attribute to forward your agent to the remote server
- **HostName**: you can use this attribute to get the real name of the host to connect to
- **IdentityFile**: you can use this attribute to set the keys to try when connecting to remote host.
- **KexAlgorithms**: you can use this attribute to configure Key exchange methods with `session.method_pref(MethodType::Kex, algos.to_string().as_str())`
- **MACs**: you can use this attribute to configure the MAC algos with `session.method_pref(MethodType::MacCs, algos..to_string().as_str())` and `session.method_pref(MethodType::MacSc, algos..to_string().as_str())`
- **Port**: you can use this attribute to resolve the port to connect to
- **ProxyJump**: you can use this attribute to specify hosts to jump via
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
ssh2-config = "^0.5"
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
    // KEX
    if let Err(err) = session.method_pref(
        MethodType::Kex,
        params.kex_algorithms.algorithms().join(",").as_str(),
    ) {
        panic!("Could not set KEX algorithms: {}", err);
    }

    // host key
    if let Err(err) = session.method_pref(
        MethodType::HostKey,
        params.host_key_algorithms.algorithms().join(",").as_str(),
    ) {
        panic!("Could not set host key algorithms: {}", err);
    }

    // ciphers
    if let Err(err) = session.method_pref(
        MethodType::CryptCs,
        params.ciphers.algorithms().join(",").as_str(),
    ) {
        panic!("Could not set crypt algorithms (client-server): {}", err);
    }
    if let Err(err) = session.method_pref(
        MethodType::CryptSc,
        params.ciphers.algorithms().join(",").as_str(),
    ) {
        panic!("Could not set crypt algorithms (server-client): {}", err);
    }

    // mac
    if let Err(err) = session.method_pref(
        MethodType::MacCs,
        params.mac.algorithms().join(",").as_str(),
    ) {
        panic!("Could not set MAC algorithms (client-server): {}", err);
    }
    if let Err(err) = session.method_pref(
        MethodType::MacSc,
        params.mac.algorithms().join(",").as_str(),
    ) {
        panic!("Could not set MAC algorithms (server-client): {}", err);
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

---

## How host parameters are resolved

This topic has been debated a lot over the years, so finally since 0.5 this has been fixed to follow the official ssh configuration file rules, as described in the MAN <https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#DESCRIPTION>.

> Unless noted otherwise, for each parameter, the first obtained value will be used. The configuration files contain sections separated by Host specifications, and that section is only applied for hosts that match one of the patterns given in the specification. The matched host name is usually the one given on the command line (see the CanonicalizeHostname option for exceptions).
>
> Since the first obtained value for each parameter is used, more host-specific declarations should be given near the beginning of the file, and general defaults at the end.

This means that:

1. The first obtained value parsing the configuration top-down will be used
2. Host specific rules ARE not overriding default ones if they are not the first obtained value
3. If you want to achieve default values to be less specific than host specific ones, you should put the default values at the end of the configuration file using `Host *`.
4. Algorithms, so `KexAlgorithms`, `Ciphers`, `MACs` and `HostKeyAlgorithms` use a different resolvers which supports appending, excluding and heading insertions, as described in the man page at ciphers: <https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Ciphers>. They are in case appended to default algorithms, which are either fetched from the openssh source code or set with a constructor. See [configuring default algorithms](#configuring-default-algorithms) for more information.

### Resolvers examples

```ssh
Compression yes

Host 192.168.1.1
    Compression no
```

If we get rules for `192.168.1.1`, compression will be `yes`, because it's the first obtained value.

```ssh
Host 192.168.1.1
    Compression no

Host *
    Compression yes
```

If we get rules for `192.168.1.1`, compression will be `no`, because it's the first obtained value.

If we get rules for `172.168.1.1`, compression will be `yes`, because it's the first obtained value MATCHING the host rule.

```ssh
Host 192.168.1.1
    Ciphers +c
```

If we get rules for `192.168.1.1`, ciphers will be `a,b,c`, because default is set to `a,b` and `+c` means append `c` to the list.

---

## Configuring default algorithms

To reload algos, build ssh2-config with `RELOAD_SSH_ALGO` env variable set.

When you invoke `SshConfig::default`, the default algorithms are set from openssh source code, which are the following:

```txt
ca_signature_algorithms:
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",

ciphers:
    "chacha20-poly1305@openssh.com",
    "aes128-ctr,aes192-ctr,aes256-ctr",
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com",

host_key_algorithms:
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",

kex_algorithms:
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr,aes192-ctr,aes256-ctr",
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr,aes192-ctr,aes256-ctr",
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "none,zlib@openssh.com",
    "none,zlib@openssh.com",

mac:
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",

pubkey_accepted_algorithms:
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
```

If you want you can use a custom constructor `SshConfig::default().default_algorithms(prefs)` to set your own default algorithms.

---

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
