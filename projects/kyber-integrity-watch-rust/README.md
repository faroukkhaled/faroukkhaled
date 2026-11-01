# KYBER Integrity Watch

Local file-integrity baselines and change detection using SHA-256.

**Status: v0.1 portfolio implementation.** Created by Farouk Khaled for the KYBER portfolio. This is new work created in November 2026, not a historical client deployment.

## Features

- Deterministic manifest creation and added/changed/missing detection.
- Rejects unsafe manifest paths and duplicate entries.
- Skips symlinks and common generated folders; never modifies scanned files.

## Technology

Rust 2021 edition. No third-party runtime dependencies.

## Run

```sh
cargo run -- snapshot PATH_TO_DIRECTORY ../baseline.tsv
cargo run -- verify PATH_TO_DIRECTORY ../baseline.tsv
```

## Verify

```sh
cargo test
```

See [VALIDATION.md](VALIDATION.md) for the checks actually run in the authoring environment.

## Scope and limitations

- The manifest must be outside the scanned root and must be trusted separately.
- SHA-256 code is tested against standard vectors but has not been independently audited.
- Not a real-time monitor. No signed baselines or race-resistant filesystem snapshot.
- 20 MiB per file and 10000-file limit. Exit 0 no differences, 1 differences, 2 errors.

## Repository layout

Source, configuration, synthetic sample data and tests are kept in this repository. Runtime databases and generated reports are ignored. Never commit client data, credentials or unredacted reports.

## Roadmap

- Broaden test fixtures and error recovery coverage.
- Gather real usability feedback using synthetic data.
- Version the data format before adding import/migration features.

## Security

Report concerns privately through the contact options on [the maintainer profile](https://github.com/faroukkhaled). Do not include secrets in public issues. See [SECURITY.md](SECURITY.md).

## License

No license has been granted yet. Contact the author before reuse or redistribution.
