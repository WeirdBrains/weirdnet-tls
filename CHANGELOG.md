# Changelog

All notable changes to weirdnet-tls are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-20

### Changed

- `cert::valid_name` and `AcmeConfig::validate` refuse `localhost`, `*.localhost`, IP addresses and all-digit top labels, which public CAs never certify.
- `AcmeConfig` is `#[non_exhaustive]`: build it with `AcmeConfig::new` and set fields.
- `HookDns` has private fields (build it with `HookDns::new`); on Windows it runs `cmd /S /C "COMMAND"` with the command unquoted.
- `Acme::load` fills `Status::next_attempt` (and `ari`) from the store.

### Added

- `cert::valid_private_name` and `AcmeConfig::private_names` for private CAs that certify such names.
- `acme::schedule`, `Acme::schedule` and `renew::Schedule`: the next renewal from the store alone, for status commands.
- `Acme::with_default_cert`: the ACME certificate also answers handshakes without SNI or for other names.
- `Resolver::set_default_as`, `set_default_pair` and `default_source`: a default certificate with its own source.
- `Acme::trigger_renewal`: a forced renewal from the background renewer, still behind the repeat-certificate guard.
- `challenge::serve_tls_alpn01`, `Resolver::challenge_config` and `Acme::serve_challenge`: challenge-only listeners for TLS-ALPN-01 and HTTP-01 while the app isn't running.
- `store::import`, `store::Legacy` and `Acme::import`: copy an app's earlier account, certificate and state into a store, never overwriting.
- `HookDns::with_prefix` and `HookDns::with_env`: DNS hooks get the record variables under an app's own prefix, and fixed extras.

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

[Unreleased]: https://github.com/WeirdBrains/weirdnet-tls/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/WeirdBrains/weirdnet-tls/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/WeirdBrains/weirdnet-tls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeirdBrains/weirdnet-tls/compare/cb06c89...v0.1.0
