# Build every target in debug mode.
[group('build')]
build args="":
  cargo build --all-targets {{ args }}

# Build every target in release mode.
[group('build')]
release args="":
  cargo build --all-targets --release {{ args }}

[group('build')]
reload_ssh_algos:
  cargo build --features reload-ssh-algo

# Remove Cargo build artifacts.
[group('build')]
[confirm("Are you sure you want to clean the build artifacts?")]
clean:
  cargo clean
