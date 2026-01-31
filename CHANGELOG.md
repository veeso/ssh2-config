# Changelog

- [Changelog](#changelog)
    - [0.6.6](#066)
    - [0.6.5](#065)
    - [0.6.4](#064)
    - [0.6.3](#063)
    - [0.6.2](#062)
    - [0.6.1](#061)
    - [0.6.0](#060)
    - [0.5.4](#054)
    - [0.5.1](#051)
    - [0.5.0](#050)
    - [0.4.0](#040)
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

## 0.6.6

Released on 31/01/2026

- Multiple `IdentityFile` directives are now accumulated instead of following first-value-wins rule, matching OpenSSH behavior.
- [Issue 43](https://github.com/veeso/ssh2-config/issues/43): Parser now correctly preserves `#` characters inside quoted strings instead of treating them as comments.
- [Issue 45](https://github.com/veeso/ssh2-config/issues/45): Parser now returns an error for mismatched quotes instead of silently ignoring them.

## 0.6.5

Released on 14/01/2026

- [Issue 37](https://github.com/veeso/ssh2-config/issues/37): KEX Algorithms were invalidly extracted
    - Also removed duplicated and invalid algorithms from the default list.

## 0.6.4

Released on 13/01/2026

- Auto generate default supported algorithms documentation on build

## 0.6.3

Released on 13/01/2026

- [Issue 32](https://github.com/veeso/ssh2-config/issues/32): Added missing field to serializer:
    - `AddKeysToAgent`
    - `ForwardAgent`
    - `ProxyJump`
- [Issue 33](https://github.com/veeso/ssh2-config/issues/33): Parse `~` in include paths.
- [Issue 34](https://github.com/veeso/ssh2-config/issues/34): Fix parsing of multiple algos on the same row.
- Updated default algos to `V_10_2_P1`

## 0.6.2

Released on 25/09/2025

- fix: Identify the root/default host when serialising (#27)
- fix: Combine host declarations when serialising (#28)
- fix: Add AddKeysToAgent, ForwardAgent, ProxyJump fields (#29)

Developed by [@milliams](https://github.com/milliams)

## 0.6.1

Released on 25/09/2025

- [Issue 30](https://github.com/veeso/ssh2-config/issues/30): Host blocks from included files didn't get registered.
  Fixed that.

## 0.6.0

Released on 15/08/2025

- Added a new constructor `SshConfig::from_hosts()` to build a `SshConfig` from a list of `Host`.
- If `Include` directive contains a relative path, it must be resolved to `$HOME/.ssh/${PATH}`
- Updated ssh default algos to `V_10_0_P2`

## 0.5.4

Released on 27/03/2025

- on docsrs DON'T build algos. It's not allowed by docs.rs
- added `RELOAD_SSH_ALGO` env variable to rebuild algos.

## 0.5.1

Released on 27/03/2025

- build was not included in the package. Fixed that.

## 0.5.0

Released on 27/03/2025

- [issue 22](https://github.com/veeso/ssh2-config/issues/22): should parse tokens with `=` and quotes (`"`)
- [issue 21](https://github.com/veeso/ssh2-config/issues/21): Finally fixed how parameters are applied to host patterns
- Replaced algorithms `Vec<String>` with `Algorithms` type.
    - The new type is a variant with `Append`, `Head`, `Exclude` and `Set`.
    - This allows to **ACTUALLY** handle algorithms correctly.
    - To pass to ssh options, use `algorithms()` method
    - Beware that when accessing the internal vec, you MUST care of what it means for that variant.
- Replaced `HostParams::merge` with `HostParams::overwrite_if_none` to avoid overwriting existing values.
- Added default Algorithms to the SshConfig structure. See readme for details on how to use it.

## 0.4.0

Released on 15/03/2025

- Added support for `Include` directive. <https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Include>
- Fixed ordering in appliance of options. **It's always top-bottom**.
- Added logging to parser. You can now disable logging by using `nolog` feature.
- `parse_default_file` is now available to Windows users
- Added `Display` and `ToString` traits for `SshConfig` which serializes the configuration into ssh2 format

## 0.3.0

Released on 19/12/2024

- thiserror `2.0`
- ‼️ **BREAKING CHANGE**: Added support for unsupported fields:

  `AddressFamily, BatchMode, CanonicalDomains, CanonicalizeFallbackLock, CanonicalizeHostname, CanonicalizeMaxDots, CanonicalizePermittedCNAMEs, CheckHostIP, ClearAllForwardings, ControlMaster, ControlPath, ControlPersist, DynamicForward, EnableSSHKeysign, EscapeChar, ExitOnForwardFailure, FingerprintHash, ForkAfterAuthentication, ForwardAgent, ForwardX11, ForwardX11Timeout, ForwardX11Trusted, GatewayPorts, GlobalKnownHostsFile, GSSAPIAuthentication, GSSAPIDelegateCredentials, HashKnownHosts, HostbasedAcceptedAlgorithms, HostbasedAuthentication, HostKeyAlias, HostbasedKeyTypes, IdentitiesOnly, IdentityAgent, Include, IPQoS, KbdInteractiveAuthentication, KbdInteractiveDevices, KnownHostsCommand, LocalCommand, LocalForward, LogLevel, LogVerbose, NoHostAuthenticationForLocalhost, NumberOfPasswordPrompts, PasswordAuthentication, PermitLocalCommand, PermitRemoteOpen, PKCS11Provider, PreferredAuthentications, ProxyCommand, ProxyJump, ProxyUseFdpass, PubkeyAcceptedKeyTypes, RekeyLimit, RequestTTY, RevokedHostKeys, SecruityKeyProvider, SendEnv, ServerAliveCountMax, SessionType, SetEnv, StdinNull, StreamLocalBindMask, StrictHostKeyChecking, SyslogFacility, UpdateHostKeys, UserKnownHostsFile, VerifyHostKeyDNS, VisualHostKey, XAuthLocation`

  If you want to keep the behaviour as-is, use `ParseRule::STRICT | ParseRule::ALLOW_UNSUPPORTED_FIELDS` when calling
  `parse()` if you were using `ParseRule::STRICT` before.

  Otherwise you can now access unsupported fields by using the `unsupported_fields` field on the `HostParams` structure
  like this:

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

- Added `ParseRule` field to `parse()` method to specify some rules for parsing. ❗ To keep the behaviour as-is use
  `ParseRule::STRICT`

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
