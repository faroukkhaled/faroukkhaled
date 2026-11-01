# KYBER Access Review

Offline role-inheritance and permission-policy review with guarded graph traversal.

**Status: v0.1 portfolio implementation.** Created by Farouk Khaled for the KYBER portfolio. This is new work created in November 2026, not a historical client deployment.

## Features

- Expands inherited roles and rejects cycles or excessive nesting.
- Flags wildcard access, public write/admin and externally shared sensitive resources.
- Escapes HTML report content and deduplicates effective-access findings.

## Technology

Rust 2021 edition. No third-party runtime dependencies.

## Run

```sh
cargo run -- sample.tsv --html report.html
```

## Verify

```sh
cargo test
```

See [VALIDATION.md](VALIDATION.md) for the checks actually run in the authoring environment.

## Scope and limitations

- TSV policy model is illustrative; it is not an AWS, Azure or GitHub permissions parser.
- Input records: grant<TAB>principal<TAB>resource<TAB>actions<TAB>scope, or member<TAB>principal<TAB>role:name.
- Scope must be internal, external or public; actions are comma-separated.
- Reports contain principal/resource identifiers. Exit 0 no signals, 1 signals, 2 errors.

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
