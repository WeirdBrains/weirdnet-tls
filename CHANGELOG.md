# Changelog

All notable changes to weirdnet-tls are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `cert::valid_name` and `AcmeConfig::validate` refuse `localhost`, `*.localhost`, IP addresses and all-digit top labels, which public CAs never certify.
- `AcmeConfig` is `#[non_exhaustive]`: build it with `AcmeConfig::new` and set fields.

### Added

- `cert::valid_private_name` and `AcmeConfig::private_names` for private CAs that certify such names.

## [0.2.0] - 2026-11-16

### Added

- `AcmeConfig::profile_optional`: when the CA refuses the profile, order with its default instead.

## [0.1.0] - 2026-11-16

### Added

- ACME certificates over instant-acme: accounts, several names, profiles, Let's Encrypt or any directory.
- TLS-ALPN-01, HTTP-01 and DNS-01 challenges, with DNS by hook command, manual prompt or grindvakt-core.
- Certificate stores: files (0600), memory, and an encrypted weirdnet-storage table.
- An SNI resolver with hot swap, pinned certificates and user, ACME and self-signed sources.
- Renewal by ACME Renewal Information or at two thirds of the lifetime, with backoff and a typed status.
- A mock ACME CA for tests (feature `testing`).

[Unreleased]: https://github.com/WeirdBrains/weirdnet-tls/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/WeirdBrains/weirdnet-tls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeirdBrains/weirdnet-tls/compare/cb06c89...v0.1.0
