# Changelog

All notable changes to weirdnet-tls are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-16

### Added

- ACME certificates over instant-acme: accounts, several names, profiles, Let's Encrypt or any directory.
- TLS-ALPN-01, HTTP-01 and DNS-01 challenges, with DNS by hook command, manual prompt or grindvakt-core.
- Certificate stores: files (0600), memory, and an encrypted weirdnet-storage table.
- An SNI resolver with hot swap, pinned certificates and user, ACME and self-signed sources.
- Renewal by ACME Renewal Information or at two thirds of the lifetime, with backoff and a typed status.
- A mock ACME CA for tests (feature `testing`).

[Unreleased]: https://github.com/WeirdBrains/weirdnet-tls/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/WeirdBrains/weirdnet-tls/compare/cb06c89...v0.1.0
