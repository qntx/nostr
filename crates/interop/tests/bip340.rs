//! Executes `vectors/bip340/official.csv` against rust-nostr's key/signature
//! types and the `secp256k1` crate it builds on.

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

mod common;

use common::{unhex, unhex_arr};
use nostr::prelude::{Keys, SecretKey};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/bip340/official.csv"
));

struct Vector<'a> {
    index: &'a str,
    secret_key: &'a str,
    aux_rand: &'a str,
    pubkey: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    expected: bool,
    comment: &'a str,
}

fn parse_row(line: &str) -> Vector<'_> {
    let mut fields = line.splitn(8, ',');
    let index = fields.next().expect("index");
    let secret_key = fields.next().expect("secret key");
    let pubkey = unhex(fields.next().expect("public key")).expect("public key hex");
    let aux_rand = fields.next().expect("aux_rand");
    let message = unhex(fields.next().expect("message")).expect("message hex");
    let signature = unhex(fields.next().expect("signature")).expect("signature hex");
    let result = fields.next().expect("verification result");
    let comment = fields.next().unwrap_or("");
    assert!(
        result == "TRUE" || result == "FALSE",
        "vector {index}: unknown result {result}"
    );
    Vector {
        index,
        secret_key,
        aux_rand,
        pubkey,
        message,
        signature,
        expected: result == "TRUE",
        comment,
    }
}

fn parse_vectors(csv: &str) -> Vec<Vector<'_>> {
    let mut rows = csv.lines();
    let header = rows.next().expect("csv header");
    assert!(
        header.starts_with("index,secret key,public key,"),
        "unexpected BIP-340 csv header: {header}"
    );
    rows.filter(|line| !line.is_empty())
        .map(parse_row)
        .collect()
}

/// nostr keys and signatures are 32/64-byte fixed: rows with other message
/// sizes cannot be expressed and are skipped.
const fn is_event_id_sized(row: &Vector<'_>) -> bool {
    row.message.len() == 32
}

#[test]
fn bip340_official() {
    let all = parse_vectors(VECTORS);
    let rows: Vec<&Vector<'_>> = all.iter().filter(|row| is_event_id_sized(row)).collect();
    let skipped = all.len() - rows.len();
    let secp = secp256k1::Secp256k1::new();
    let mut signed_rows = 0_u32;
    for row in &rows {
        let message = row.message.as_slice();
        let pubkey: [u8; 32] =
            <[u8; 32]>::try_from(row.pubkey.as_slice()).expect("vector pubkey is 32 bytes");
        let signature = secp256k1::schnorr::Signature::from_slice(&row.signature)
            .expect("vector signature is 64 bytes");
        let x_only = secp256k1::XOnlyPublicKey::from_byte_array(&pubkey);

        if !row.secret_key.is_empty() {
            // Signing rows also pin secret -> public derivation.
            let secret =
                SecretKey::from_hex(row.secret_key).expect("vector secret key is a scalar");
            let keys = Keys::new(secret);
            assert_eq!(
                keys.public_key().to_bytes(),
                pubkey,
                "vector {}: derived public key",
                row.index
            );
            let aux = unhex_arr::<32>(row.aux_rand).expect("aux hex");
            let signed = keys.sign_schnorr_with_aux_rand(&secp, message, &aux);
            assert_eq!(
                signed.to_bytes(),
                row.signature.as_slice(),
                "vector {}: signature",
                row.index
            );
            signed_rows += 1;
        }

        // A non-point public key cannot verify — rust-secp256k1's
        // `from_byte_array` rejects it, which is the same "FALSE" outcome.
        let verifies = x_only.is_ok_and(|pk| secp.verify_schnorr(&signature, message, &pk).is_ok());
        assert_eq!(
            verifies, row.expected,
            "vector {}: {}",
            row.index, row.comment
        );
    }
    assert!(
        signed_rows > 0,
        "no BIP-340 signing rows ran for vectors/bip340/official.csv"
    );
    assert_eq!(rows.len(), 15, "executed row count changed");
    assert_eq!(skipped, 4, "skipped row count changed");
}
