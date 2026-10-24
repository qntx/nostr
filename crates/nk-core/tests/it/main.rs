//! Shared-vector conformance: every `core.*` capability from
//! `parity.json` plus the official BIP-340 CSV, run against `nk-core`
//! with no divergence registry, skip list, or expected-failure list.

#![allow(
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "an integration-test binary is a test module by construction"
)]

mod bip340;
mod common;
mod core;
