# Contributing

Thank you for helping make Umbera's cryptography better.

## Get the code and run the tests

```bash
git clone https://github.com/UmberaAPP/UMBERA.git
cd UMBERA/core
cargo test
```

You need a stable Rust toolchain (1.85 or newer). Fuzzing needs nightly and `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cd core/fuzz && cargo +nightly fuzz run amf_parse
```

## Pull requests

- Keep changes small and focused; one topic per pull request.
- Add or update tests for any behaviour you change. `cargo test` must pass.
- Do not change wire formats or domain-separation labels without discussing it first in an issue —
  the apps depend on them byte for byte (see [docs/PROTOCOL.md](docs/PROTOCOL.md)).
- By submitting a pull request you agree that your contribution is licensed under the
  [Apache License 2.0](LICENSE).

## Where to start

Look for issues labelled
[good first issue](https://github.com/UmberaAPP/UMBERA/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22),
or ask in [Discussions](https://github.com/UmberaAPP/UMBERA/discussions).

Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
