alias lint := clippy

# Format Markdown, Rust, TOML, and YAML files.
[group('code-check')]
fmt args="":
  dprint fmt {{ args }}

# Check formatting without changing files.
[group('code-check')]
fmt_check args="":
  dprint check {{ args }}

# Run Clippy for every target.
[group('code-check')]
clippy args="":
  cargo clippy --all-targets {{ args }}

# Build Rust documentation and deny warnings.
[group('code-check')]
doc args="":
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps {{ args }}

# Check advisories, licenses, bans, and dependency sources.
[group('code-check')]
deny args="":
  cargo deny check {{ args }}

# Scan paths for verified or unknown secrets.
[group('code-check')]
scan_secrets *args=".":
  trufflehog filesystem {{ args }} --results=verified,unknown --fail --fail-on-scan-errors --no-update

# Regenerate and verify the OpenSSH default algorithms.
[group('code-check')]
check_default_algorithms:
  cargo build --features reload-ssh-algo
  rustup run nightly rustfmt --edition 2024 src/default_algorithms/openssh.rs
  git diff --exit-code -- src/default_algorithms/openssh.rs

# Run the complete local quality gate.
[group('code-check')]
check:
  just fmt_check
  just clippy "-- -D warnings"
  just doc
  just deny
  just test
