//! Shared-vector conformance: every `core.*` capability from
//! `parity.json` plus the official BIP-340 CSV, run against `nk-core`
//! with no divergence registry, skip list, or expected-failure list.

#![allow(
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "an integration-test binary is a test module by construction"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::redundant_closure_for_method_calls,
    clippy::option_if_let_else,
    clippy::excessive_nesting,
    clippy::shadow_unrelated,
    clippy::missing_assert_message,
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    clippy::or_fun_call,
    clippy::str_to_string,
    clippy::doc_markdown,
    clippy::redundant_closure,
    reason = "malformed fixtures must fail the vector tests loudly"
)]

mod bip340;
mod common;
mod core;
mod diff;
mod nip10;
mod nip13;
#[cfg(feature = "nip44")]
mod nip17;
mod nip19;
mod nip21;
mod nip27;
mod nip42;
mod nip46;
mod nip51;
mod nip57;
mod nip65;
mod nip98;
