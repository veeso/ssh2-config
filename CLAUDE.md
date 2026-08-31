# CLAUDE.md

This file provides guidance to Claude Code when working with code in this
repository.

`AGENTS.md` is a symbolic link to this file so every coding agent uses the same
repository contract.

## Commands

Every recurring task runs through a [`just`](https://just.systems) recipe. Do
not bypass a recipe with an ad hoc Cargo or tool command. If a recurring task
has no recipe, add one under `just/` before using it. Run `just` to list all
recipes.

```sh
just build                         # Build all targets.
just release                       # Build all targets in release mode.
just test                          # Run target and documentation tests.
just coverage                      # Write LCOV coverage to lcov.info.
just fmt                           # Format Markdown, Rust, TOML, and YAML.
just fmt_check                     # Check formatting without changes.
just lint "-- -D warnings"         # Run Clippy and deny warnings.
just doc                           # Build documentation and deny warnings.
just deny                          # Audit dependencies with cargo-deny.
just scan_secrets                  # Scan the repository with TruffleHog.
just check_default_algorithms      # Verify generated OpenSSH algorithms.
just check                         # Run the complete local quality gate.
just changelog_preview 0.8.0       # Preview an unreleased changelog.
just changelog 0.8.0               # Generate CHANGELOG.md.
just publish "--dry-run --allow-dirty"
```

Tests that parse the default user configuration require `~/.ssh/config` to
exist; it may be empty.

To run one test, pass its filter through the recipe:

```sh
just test "parse_remote_forward"
just test "-- --nocapture"
```

Never request build or test parallelism above eight from the command line. This
is an invocation constraint only; do not encode the cap in tracked files.

If a required tool is missing, report it. Never claim a check passed or replace
it silently with a weaker command.

## Architecture

`ssh2-config` is a library crate that parses OpenSSH client configuration for
the `ssh2` crate. It applies OpenSSH's first-obtained-value rule while combining
global directives and matching `Host` blocks.

- `src/lib.rs` exposes `SshConfig`, the main parse, query, and serialization
  API.
- `src/parser.rs` and `src/parser/field.rs` tokenize directives, resolve
  includes, and populate host parameters.
- `src/params.rs` and `src/params/` define supported SSH options and algorithm
  list operations.
- `src/host.rs` implements wildcard and negated host matching.
- `src/serializer.rs` writes parsed configurations back to OpenSSH syntax.
- `build/` regenerates `src/default_algorithms/openssh.rs` from a pinned
  OpenSSH source tag when the `reload-ssh-algo` feature is enabled.

The `reload-ssh-algo` feature is intentionally excluded from general lint and
documentation recipes: enabling it clones OpenSSH and rewrites generated
source. Use `just check_default_algorithms` for that path.

## Tooling

- `Justfile` imports grouped recipes from `just/`.
- `dprint.json` formats Markdown, TOML, and YAML directly and delegates Rust
  files to nightly rustfmt.
- `cliff.toml` generates `CHANGELOG.md` from Conventional Commits.
- `deny.toml` enforces advisory, license, duplicate, wildcard, and source
  policy for every feature.
- `.github/workflows/ci.yml` drives build and quality jobs through `just`.
- Dedicated workflows audit GitHub Actions with zizmor and scan secrets with
  TruffleHog.

## Conventions

- Use `module_name.rs`; never add `mod.rs`.
- Public library items require canonical rustdoc and runnable examples.
- Use named format placeholders instead of positional `{}` placeholders.
- Prefer `#[expect]` with a reason over `#[allow]`.
- Keep Cargo dependencies and features alphabetically sorted and use minimal,
  bare versions.
- Follow Conventional Commits with imperative, lower-case subjects. Do not add
  agent attribution, session links, or agent `Co-Authored-By` lines.
- After changing a Markdown file containing a table, run
  `fmt-md-tables -i <file>`.
- After changing `.github/workflows/`, run `zizmor .github/workflows` until it
  exits cleanly.
