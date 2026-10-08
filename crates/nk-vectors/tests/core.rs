//! Executes `vectors/core/*.json` against the nk-core public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

use nk_core::{ErrorKind, RelayUrl};
use serde::Deserialize;

const URL_NORMALIZE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/url-normalize.json"
));

/// One vector case: either an expected output or the expected error kind
/// (named after the TS error class).
#[derive(Deserialize)]
struct UrlNormalizeCase {
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct UrlNormalizeVector {
    cases: Vec<UrlNormalizeCase>,
}

#[test]
fn url_normalize() {
    let vector: UrlNormalizeVector =
        serde_json::from_str(URL_NORMALIZE).expect("url-normalize.json must parse");
    assert!(!vector.cases.is_empty(), "url-normalize.json has no cases");
    let mut checked = 0_u32;
    for case in &vector.cases {
        match (&case.output, &case.error) {
            (Some(expected), None) => {
                assert_eq!(
                    RelayUrl::parse(&case.input)
                        .as_ref()
                        .map(RelayUrl::as_str)
                        .ok(),
                    Some(expected.as_str()),
                    "input {:?}",
                    case.input
                );
            }
            (None, Some(kind)) => {
                assert_eq!(
                    kind.as_str(),
                    "UrlError",
                    "input {:?}: unexpected error kind in vector",
                    case.input
                );
                assert_eq!(
                    RelayUrl::parse(&case.input).err().map(|error| error.kind()),
                    Some(ErrorKind::Url),
                    "input {:?}: expected ErrorKind::Url",
                    case.input
                );
            }
            (output, error) => {
                panic!(
                    "input {:?}: malformed case (output {output:?}, error {error:?})",
                    case.input
                );
            }
        }
        checked += 1;
    }
    assert!(checked > 0, "no url-normalize cases ran");
}
