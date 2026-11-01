# Validation

Executed on 2026-11-01 in the authoring environment.

- Runtime: Rust 1.99.0
- Command: `cargo test`
- Result: 3 tests passed: SHA-256 standard vectors (empty, abc, million-a), change types, unsafe paths and duplicates.

## Limits of verification

These checks are not a penetration test, production certification, load test or independent audit. All fixtures are synthetic. Operating-system and deployment differences may require additional validation.

The release source was reviewed for credential patterns before publication; no live credentials are included.
