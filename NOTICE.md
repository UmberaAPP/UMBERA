# Notice

Copyright © 2026 Umbera. All rights reserved except as granted by the
[PolyForm Strict License 1.0.0](LICENSE.md).

## What the license allows

This repository is **source available** so that the security of Umbera can be independently reviewed.
You may read, build and test the code, and use it for non-commercial research and evaluation.
You may not use it in a product or service, modify it, create derivative works from it, or
redistribute it.

For any other use, including commercial licensing, contact **info@umbera.app**.

## Trademarks

"Umbera", the Umbera name and the eclipse logo are trademarks of Umbera. The license does not
grant any right to use them. Applications or services must not use the Umbera name or logo, or any
confusingly similar mark, to identify themselves.

## Third-party components

The Rust core depends on third-party crates under their own licenses (MIT, Apache-2.0 or BSD),
including OpenMLS, RustCrypto (`ml-kem`, `ml-dsa`, `aes-gcm`, `hkdf`, `argon2`, `sha2`, `k256`),
dalek-cryptography (`curve25519-dalek`, `x25519-dalek`, `ed25519-dalek`), `uniffi` and `lopdf`.
They are fetched by Cargo and are not redistributed in this repository.
