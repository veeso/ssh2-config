# Run all unit, integration, example, and documentation tests.
[group('test')]
test args="":
  cargo test --all-targets {{ args }}
  cargo test --doc {{ args }}

# Generate an LCOV coverage report.
[group('test')]
coverage output="lcov.info" args="":
  cargo llvm-cov --all-targets --lcov --output-path {{ output }} {{ args }}
