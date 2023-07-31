# Changelog

- [Changelog](#changelog)
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
