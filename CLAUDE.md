# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ssh2-config is a Rust library that parses OpenSSH configuration files for use with the ssh2-rs crate.
It implements the first-value-wins rule per the SSH specification.

## Build and Test Commands

```bash
# Build
cargo build

# Run all tests
cargo test

# Run specific test
cargo test test_name

# Clippy (must pass with no warnings)
cargo clippy -- -Dwarnings

# Format (requires nightly)
cargo +nightly fmt --all --check   # check only
cargo +nightly fmt                  # apply formatting

# Run examples
cargo run --example query -- <host> [config-path]
cargo run --example print -- [config-path]
cargo run --example client -- <host> [config-path]

# Regenerate default algorithms from OpenSSH source
RELOAD_SSH_ALGO=1 cargo build
```

**Test environment setup:** Tests require `~/.ssh/config` to exist (can be empty).

## Architecture

### Core Types

- **SshConfig** (`lib.rs`): Main entry point. Parses config via `parse()`, queries hosts via `query(pattern)`,
  serializes via `to_string()`
- **HostParams** (`params.rs`): All configuration parameters for a host (port, user, identity files, algorithms, etc.)
- **Host** (`host.rs`): Pattern-based host matching with wildcard (`*`, `?`) and negation (`!`) support
- **Algorithms** (`params/algos.rs`): Algorithm list with modification rules (Set, Append `+`, Exclude `-`, Head `^`)

### Parsing Flow

1. Parser reads config top-down, applying first-value-wins rule
2. `Include` directives are resolved recursively with glob support
3. Algorithm fields accumulate modifications (append/exclude/head) applied to defaults
4. `query()` merges matching Host blocks via `HostParams::overwrite_if_none()`

### Key Files

- `src/parser.rs` + `src/parser/field.rs`: Tokenization and field parsing
- `src/default_algorithms/openssh.rs`: Build-time generated algorithm defaults
- `build/main.rs`: Build script that can regenerate algorithms from OpenSSH source

### ParseRule Flags

- `STRICT`: Reject unknown/unsupported fields
- `ALLOW_UNKNOWN_FIELDS`: Accept completely unknown fields
- `ALLOW_UNSUPPORTED_FIELDS`: Accept recognized but unsupported fields (accessible via `params.unsupported_fields`)

## Code Style

- Follow Conventional Commits: `type(scope): message`
- Minimize dependencies
- Write tests for new features
- Clippy must pass with `-Dwarnings`
- Format with nightly rustfmt

## Reference Documentation

- `docs/ssh_config.5.md`: OpenSSH ssh_config(5) man page reference for all supported configuration options
