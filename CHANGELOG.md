# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-08
### Added
- `redact`, `createRedactor`, `redactString`, `redactRequest`, `maskValue`.
- Key-based redaction (case/punctuation-insensitive) with custom keys and RegExps.
- Value detectors: JWT, Bearer tokens, Luhn-validated credit cards, emails (opt-in).
- Circular reference, max-depth, Error, Date, Map, Set and Buffer handling.
- TypeScript type definitions.
