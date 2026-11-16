# Security notes for weirdnet-tls

This describes what the crate does to keep keys and TLS safe. It is not an audit.

- Private keys and ACME account credentials only go to the `CertStore`. `FileStore` writes them
  to files with mode 0600 in directories 0700 (Unix), through a temporary file and a rename.
  `SqlStore` keeps them in a weirdnet-storage (SQLCipher) database. `CertPair`'s `Debug`
  hides the key.
- Store keys are checked (`a-z0-9._-/`, no `..`), so a certificate set id cannot escape the
  store directory.
- A TLS-ALPN-01 validation (ALPN `acme-tls/1`) is answered only with the challenge certificate,
  and never with a real one; other handshakes never get a challenge certificate. Answers are
  withdrawn when the order ends, whether it succeeded or not.
- The HTTP-01 listener answers only published tokens and returns 404 for everything else. It
  does not redirect or serve content, so it never stands in for HTTPS.
- When an order fails, the previous certificate stays in service (or the self-signed one); the
  crate never falls back to plain HTTP. Failures back off from 1 hour to 1 day, and forced
  renewals within a day of the last issue are refused, to stay inside CA rate limits.
- A certificate from the CA is installed only if its key matches and it covers every
  configured name.
- DNS-01 hook commands run through the shell with the record in environment variables, never
  in the command line. The hook command itself comes from your configuration; treat it as code.
- `GrindvaktDns` cannot delete records, so the last `_acme-challenge` TXT value stays
  published. It only proves control for an order that has already finished.

Report security problems to m3talsmith@gmail.com.
