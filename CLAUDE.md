# koon — development notes

Rust workspace with native bindings. `crates/core` holds the HTTP/TLS engine;
`crates/cli`, `crates/node`, `crates/python` and `crates/r` are thin wrappers
around it.

## Build and test

```bash
cargo fmt                     # CI fails on unformatted code — run before every commit
cargo build --release -p koon-cli
cargo test -p koon-core                              # unit + offline tests
cargo test -p koon-core --test fingerprint -- --ignored   # JA3/JA4/Akamai vs tls.browserleaks.com
```

The fingerprint tests need network access. They compare against hashes captured
from real browsers — a failure means a profile drifted, not that the test is flaky.

## Adding a browser version

Version support lives in `crates/core/src/profile/`. Each factory exposes
`MIN_VERSION`/`LATEST_VERSION` (Safari uses the `SAFARI_VERSIONS` table instead);
the CLI listing, error messages and the roundtrip test all derive from those, so
they do not need separate edits. What does need touching:

1. `crates/core/src/profile/<browser>.rs` — bump `LATEST_VERSION`, add the
   `vNNN_*` convenience constructors, point `latest()` at the new version.
   Opera additionally needs its Chromium mapping extended.
2. `crates/core/tests/fingerprint.rs` — add a test for the new version.
3. `README.md` — the profile tables and the total profile count.
4. `CHANGELOG.md` under `[Unreleased]`.
5. `~/.claude/koon-reference.md` — the profile count quoted there.

**Never guess a fingerprint.** Capture the real browser first. The profile
matrix is generated, so a wrong constant silently affects every OS variant of
that version.

## Capturing a real ClientHello

Point a browser at a local TCP listener and parse the first record — the
ClientHello arrives before any certificate, so an untrusted endpoint is fine:

```bash
chrome.exe --headless=new --ignore-certificate-errors https://127.0.0.1:PORT/
firefox.exe -headless -no-remote -profile <dir> https://127.0.0.1:PORT/
```

Old versions come from [Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/)
and [archive.mozilla.org](https://archive.mozilla.org/pub/firefox/releases/)
(the Windows installer unpacks with 7-Zip). Chrome for Testing runs without
Finch experiments, so confirm anything it shows against a real stable build
before treating it as the shipped behaviour.

For hashes rather than raw bytes, `https://tls.browserleaks.com/json` returns
JA3/JA3N/JA4 and the Akamai H2 fingerprint. Note that `tls.peet.ws` has been
serving an invalid certificate.

## Version-dependent fingerprints

Not every version differs only in its User-Agent. Current exceptions, all
verified by capture:

- Chrome ≤134 uses ALPS codepoint `0x4469`, ≥135 uses `0x44CD`.
- Chromium ≥150 prepends the ML-DSA signature algorithms (`0x0904`–`0x0906`)
  — affects Chrome, Edge and Opera via its Chromium base.
- Firefox ≥151 dropped `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (`0xc009`).

BoringSSL rejects signature algorithms it cannot verify, so ML-DSA needs
`btls-sys/patches/mldsa-verify-prefs.patch` in the [btls fork](https://github.com/scrape-hub/btls).
`crates/core/src/tls/sigalgs.rs` maps names to raw code points for it.

## Releasing

Version numbers live in `Cargo.toml`, `crates/node/package.json` + `crates/node/npm/*`,
`crates/python/pyproject.toml` and `crates/r/DESCRIPTION`. The R crate's internal
`rust-crate` version is a separate line and stays as is.

Bump versions only when releasing; the changelog collects under `[Unreleased]`
in between. After a koon release, bump and publish
[koon-mcp](https://github.com/scrape-hub/koon-mcp) too — its `koonjs` dependency
is a caret range, which does not cross 0.x minor versions on its own.

CI publishes to PyPI, npm and GitHub Releases on a tag. npm publishing uses
Trusted Publishing (OIDC), so no `NPM_TOKEN` secret is involved.
