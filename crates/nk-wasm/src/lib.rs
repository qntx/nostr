#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-dependencies serve the integration tests, not the lib"
    )
)]

//! `nk-wasm`: the `nk_*` byte ABI (version 1) over `nk-core`, compiled to
//! `wasm32-unknown-unknown` as `nk_wasm.wasm` for `@qntx/nostr-wasm`.
//!
//! No wasm-bindgen: the module has zero imports and exports `memory` plus
//! `nk_abi_version`, `nk_verify`, `nk_verify_serialized`, `nk_sign`,
//! `nk_public_key`, and (wasm32 only) the `nk_buffer` scratch region — every
//! crypto operation delegates to `nk-core`. See `docs/nk/acceleration.mdx`.

pub mod abi;
