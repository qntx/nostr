#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-dependencies serve the integration tests, not the lib"
    )
)]

//! `qntx-nostr-wasm`: the `nostr_*` byte ABI (version 2) over `secp256k1` and
//! `sha2`, compiled to `wasm32-unknown-unknown` as `nostr_wasm.wasm` for
//! `@qntx/nostr-wasm`.
//!
//! No wasm-bindgen: the module has zero imports and exports `memory` plus
//! `nostr_abi_version`, `nostr_verify`, `nostr_verify_serialized`,
//! `nostr_sign`, `nostr_public_key`, and (wasm32 only) the `nostr_buffer`
//! scratch region. See `docs/nk/acceleration.mdx`.

pub mod abi;
