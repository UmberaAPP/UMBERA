# Notice

Umbera Core
Copyright © 2026 Umbera (https://umbera.app)

This product is licensed under the [Apache License 2.0](LICENSE).

## Trademarks

"Umbera", the Umbera name and the eclipse logo are trademarks of Umbera. The license does not
grant any right to use them (Apache License 2.0, section 6). Applications or services built with this
code must not use the Umbera name or logo, or any confusingly similar mark, to identify themselves.

## Third-party components

The Rust core depends on third-party crates under their own licenses (MIT, Apache-2.0 or BSD),
including OpenMLS (`openmls`, `openmls_rust_crypto`, `openmls_libcrux_crypto`, MIT), libcrux (the X-Wing
KEM used through `openmls_libcrux_crypto`, Apache-2.0), RustCrypto (`ml-kem`, `ml-dsa`, `aes-gcm`, `hkdf`,
`argon2`, `sha2`, `k256`), dalek-cryptography (`curve25519-dalek`, `x25519-dalek`, `ed25519-dalek`),
`uniffi` and `lopdf`. The tests also use OpenMLS 0.6 to check compatibility with the previous core.

The Go reference in `communities/pqc` depends on Cloudflare CIRCL (`github.com/cloudflare/circl`,
BSD-3-Clause) and `golang.org/x/crypto` (BSD-3-Clause).

These components are fetched by Cargo and Go and are not redistributed in this repository.
