# Changelog

All notable changes to this project are documented in this file.

## 0.8.0

Released on 2026-08-31

### Breaking changes

- **api:** support complete remote forward specifications

> HostParams::remote_forward changes from Option<u16> to Vec<RemoteForward> and preserves listener and destination endpoints.

### Added

- Breaking: **api:** support complete remote forward specifications

### Build

- modernize project tooling

## 0.7.2

Released on 2026-08-01

### Build

- **cargo.toml:** add tls backend to git2

## 0.7.1

Released on 2026-04-26

### Added

- **build:** gate build deps behind reload-ssh-algo feature

> Replace RELOAD_SSH_ALGO env var with optional cargo feature. Makes
> anyhow and git2 (and openssl C bindings) optional build dependencies,
> only compiled when the feature is enabled.

### Fixed

- **parser:** preserve quoted spans with whitespace across multiple args (#52)

> Previously, tokenize_line only handled a single fully-quoted argument; multi-argument
> lines split on whitespace and broke quoted values containing spaces (e.g. SetEnv
> TEST="Test 2"). Introduce split_args_respecting_quotes to walk chars with quote-state,
> keeping quoted spans intact and preserving backslash escapes verbatim. Single fully-
> quoted args continue to be stripped and unescaped for backward compatibility.

## 0.7.0

Released on 2026-01-31

### Fixed

- **parser:** accumulate IdentityFile directives across Host blocks (#39) (#42)

> Multiple IdentityFile directives are now accumulated instead of
> following the first-value-wins rule, matching OpenSSH behavior where
> "Multiple IdentityFile directives will add to the list of identities
> tried".

- **parser:** preserve hash characters inside quoted strings (#43) (#47)

> The parser now correctly handles `#` characters inside quoted strings,
> treating them as part of the value rather than as comment markers.

- **parser:** return error for mismatched quotes (#45) (#48)

> - fix(parser): return error for mismatched quotes (#45)
>
> The parser now validates quotes in arguments and returns an InvalidQuotes
> error when they are mismatched, matching OpenSSH behavior.

- **parser:** handle escape sequences in quoted arguments (#44) (#49)

> Added support for escape sequences within quoted strings:
>
> - \" -> " (escaped double quote)
> - \\ -> \ (escaped backslash)
> - \' -> ' (escaped single quote)
>
> Unrecognized escape sequences preserve the backslash, matching
> OpenSSH's argv_split() behavior.

- **parser:** handle multiple '!' characters in host patterns correctly (#46) (#50)

> Only the leading '!' character indicates a negated pattern. Any subsequent
> '!' characters are now treated as literal characters in the pattern.

## 0.6.5

Released on 2026-01-14

### Fixed

- **build:** KEX Algorithms were invalidly extracted (#38)

> Also removed duplicated and invalid algorithms from the default list

## 0.6.3

Released on 2026-01-13

### Fixed

- **build:** default algos not being split by `,` (#35)

> - fix(build): default algos not being split by `,`
>
> Also updated default algos to openssh `V_10_2_P1`

- include path handling for path start with `~` (#36)

> If the path starts with '~', it now strips the prefix and prepends the home directory. This ensures correct path formation for SSH configurations.
>
> ---

- Serialise some missing fields (#32)

> Add AddKeysToAgent, ForwardAgent and ProxyJump to
> the serialiser.

## 0.6.2

Released on 2025-09-25

### Fixed

- Identify the root/default host when serialising (#27)

> The first host in the list will only be treated as
> the root host if its host pattern is exactly "*",
> otherwise it will be treated as a normal host.

- Combine host declarations when serialising (#28)

> - fix: Combine host declarations when serialising
>
> Where multiple patterns are assigned to a host,
> put them all in the same Host declaration rather
> than printing the host parameters multiple times.
>
> - style: Remove unnecessary blank line in tests module

- Add AddKeysToAgent, ForwardAgent, ProxyJump fields (#29)

> - feat: Add support for AddKeysToAgent keyword
> - feat: Add support for ForwardAgent keyword
> - feat: Add support for ProxyJump keyword

## 0.6.1

Released on 2025-09-25

### Fixed

- Host blocks from included files didn't get registered (#31)

> - fix: Host blocks from included files didn't get registered

### Build

- MRSV 1.88.0

## 0.6.0

Released on 2025-08-15

### Added

- Added a new constructor `SshConfig::from_hosts()` to build a `SshConfig` from a list of `Host`.

### Fixed

- **parser:** If `Include` directive contains a relative path, it must be resolved to `$HOME/.ssh/${PATH}`
- Updated ssh default algos to `V_10_0_P2`

### Style

- Lint

## 0.5.4

Released on 2025-03-27

### Fixed

- build for DOCS_RS.

### Build

- include openssh algos; rebuild only if env set

## 0.5.1

Released on 2025-03-27

### Breaking changes

- added Algorithms variant to handle correctly algo rules; parse top-down, allow multi hosts (#23)

> changed the API to get algorithms from Option of Vec String, to Algorithms

- fix: renamed AlgoType to AlgoOp

- fix: Replaced `HostParams::merge` with `HostParams::overwrite_if_none` to avoid overwriting existing values.

- feat!: Added Default Algorithms to SshConfig

Added default Algorithms to the SshConfig structure. See readme for details on how to use it.

### Added

- Breaking: added Algorithms variant to handle correctly algo rules; parse top-down, allow multi hosts (#23)

> - fix: first definition has priority
> - fix: don't overwrite first definition of hosts, we keep both
> - feat!: added Algorithms variant to handle correctly algo rules; parse top-down, allow multi hosts

### Fixed

- parse config entries separated with '=' or quotes (") (#24)
- include build to manifest

### Performance

- don't fetch openssh repo unless file doesn't exist or is older than a week

## 0.4.0

Released on 2025-03-15

### Breaking changes

- **parser:** Added support for Include directive; fixed ordering of parser to top-bottom

> Added support for Include directive; fixed ordering of parser to top-bottom

### Added

- Breaking: **parser:** Added support for Include directive; fixed ordering of parser to top-bottom
- `parse_default_file` is now available to Windows users
- ToString and Display for SshConfig

> It is now possible to serialize ssh2 config by using the ToString or Display trait to SshConfig

## 0.3.0

Released on 2024-12-19

### Added

- BREAKING Unsupported fields

> - Update documentation to reflect unsupported_fields field
> - Add logic for unsupported fields
> - Add a comment to the unssupported field logic
> - fix: improvements to code
> - feat: breaking 0.3
>
> ---

### Fixed

- donation link
- bump version

## 0.2.3

Released on 2023-12-05

### Fixed

- correctly apply configuration precedence in reverse parsing order (#12)

> - fix: correctly apply configuration precedence in reverse parsing order
>
> This change fixes #11:
>
> Previously, the order of precedence applied to
> parsed configuration was incorrect.
>
> Configuration was parsed, then sorted in
> alphabetical order.
>
> Algorithms (ciphers, key
> exchange algorithms, MACs, etc.) were incorrectly
> applied during parsing.
>
> The correct precedence order follows
> https://linux.die.net/man/5/ssh_config: the
> configuration is read from top to bottom,
> precedence is applied from bottom (lowest)
> to the top (highest precedence).
>
> Options preceding the first `Host` block are
> considered implicit command line options, in
> line with OpenSSH's own implementation.
>
> This patch includes the following changes:
>
> - Remove the alphabetic ordering of host sections.
> - Merge matching host sections in reverse order.
> - More efficiently merge host sections with
>   vastly reduced `clone`s. (`clone` on demand.)
> - Resolve algorithms not during the parsing,
>   but during the resolving stage.
> - More efficiently resolve algorithms, without
>   source list mutation.
> - Adjust existing unit tests to test the corrected
>   precedence algorithm.
>
> * feat: improve error-tests by matching on error enum variant
>
> This change improves error-tests by replacing
> `Result::is_err` with a match against the error
> enum.
>
> Previously, only the existence of an error result
> was checked.
>
> With the first additional commit,
> the kind of error is checked as well.
>
> - style: return `Result` from success tests, using `?` (Rust 2018 idiom)
>
> This change improves success-tests by applying
> the Rust 2018 idiom of returning `Result`
> from tests.
>
> This way, `Result::unwrap` and `Result::is_ok`
> can be replaced by `?`.
>
> Any error occurring in a success-test
> is propagated to the test runner.
>
> Some tests previously called `.ok().unwrap()` on
> `Result`s, effectively first turning them into
> `Option`s before unwrapping.
>
> This unidiomatic pattern is replaced
> by `?` as well.

## 0.2.0

Released on 2023-05-09

### Added

- Added `ParseRule` field to `parse()` method to specify some rules for parsing. ❗ To keep the behaviour as-is use `ParseRule::STRICT`

## 0.1.0

Released on 2021-12-04
