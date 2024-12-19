# Changelog

- [Changelog](#changelog)
  - [0.3.0](#030)
  - [0.2.3](#023)
  - [0.2.2](#022)
  - [0.2.1](#021)
  - [0.2.0](#020)
  - [0.1.6](#016)
  - [0.1.5](#015)
  - [0.1.4](#014)
  - [0.1.3](#013)
  - [0.1.2](#012)
  - [0.1.1](#011)
  - [0.1.0](#010)

---

## 0.3.0

Released on 19/12/2024

- thiserror `2.0`
- ‼️ **BREAKING CHANGE**: Added support for unsupported fields:

    `AddressFamily, BatchMode, CanonicalDomains, CanonicalizeFallbackLock, CanonicalizeHostname, CanonicalizeMaxDots, CanonicalizePermittedCNAMEs, CheckHostIP, ClearAllForwardings, ControlMaster, ControlPath, ControlPersist, DynamicForward, EnableSSHKeysign, EscapeChar, ExitOnForwardFailure, FingerprintHash, ForkAfterAuthentication, ForwardAgent, ForwardX11, ForwardX11Timeout, ForwardX11Trusted, GatewayPorts, GlobalKnownHostsFile, GSSAPIAuthentication, GSSAPIDelegateCredentials, HashKnownHosts, HostbasedAcceptedAlgorithms, HostbasedAuthentication, HostKeyAlias, HostbasedKeyTypes, IdentitiesOnly, IdentityAgent, Include, IPQoS, KbdInteractiveAuthentication, KbdInteractiveDevices, KnownHostsCommand, LocalCommand, LocalForward, LogLevel, LogVerbose, NoHostAuthenticationForLocalhost, NumberOfPasswordPrompts, PasswordAuthentication, PermitLocalCommand, PermitRemoteOpen, PKCS11Provider, PreferredAuthentications, ProxyCommand, ProxyJump, ProxyUseFdpass, PubkeyAcceptedKeyTypes, RekeyLimit, RequestTTY, RevokedHostKeys, SecruityKeyProvider, SendEnv, ServerAliveCountMax, SessionType, SetEnv, StdinNull, StreamLocalBindMask, StrictHostKeyChecking, SyslogFacility, UpdateHostKeys, UserKnownHostsFile, VerifyHostKeyDNS, VisualHostKey, XAuthLocation`

    If you want to keep the behaviour as-is, use `ParseRule::STRICT | ParseRule::ALLOW_UNSUPPORTED_FIELDS` when calling `parse()` if you were using `ParseRule::STRICT` before.

    Otherwise you can now access unsupported fields by using the `unsupported_fields` field on the `HostParams` structure like this:

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

## 0.2.3

Released on 05/12/2023

- Fixed the order of appliance of configuration argument when overriding occurred. Thanks @LeoniePhiline

## 0.2.2

Released on 31/07/2023

- Exposed `ignored_fields` as `Map<String, Vec<String>>` (KeyName => Args) for `HostParams`

## 0.2.1

Released on 28/07/2023

- Added `parse_default_file` to parse directly the default ssh config file at `$HOME/.ssh/config`
- Added `get_hosts` to retrieve current configuration's hosts

## 0.2.0

Released on 09/05/2023

- Added `ParseRule` field to `parse()` method to specify some rules for parsing. ❗ To keep the behaviour as-is use `ParseRule::STRICT`

## 0.1.6

Released on 03/03/2023

- Added legacy field support
  - HostbasedKeyTypes
  - PubkeyAcceptedKeyTypes

## 0.1.5

Released on 27/02/2023

- Fixed comments not being properly stripped

## 0.1.4

Released on 02/02/2023

- Fixed [issue 2](https://github.com/veeso/ssh2-config/issues/2) hosts not being sorted by priority in host query

## 0.1.3

Released on 29/01/2022

- Added missing `ForwardX11Trusted` field to known fields

## 0.1.2

Released on 11/01/2022

- Implemented `IgnoreUnknown` parameter
- Added `UseKeychain` support for MacOS

## 0.1.1

Released on 02/01/2022

- Added `IdentityFile` parameter

## 0.1.0

Released on 04/12/2021

- First release
