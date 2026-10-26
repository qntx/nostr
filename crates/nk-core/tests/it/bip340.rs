//! The official BIP-340 test vectors (`vectors/bip340/official.csv`)
//! driven against `nk-core` signing and verification.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::shadow_unrelated,
    reason = "a malformed fixture file must fail the test loudly"
)]

use nk_core::{EventId, Keys, PublicKey, SecretKey, Signature};

use crate::common::{AuxRng, unhex, unhex_arr};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/bip340/official.csv"
));

struct Row<'a> {
    index: &'a str,
    secret_key: &'a str,
    aux_rand: &'a str,
    pubkey: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    expected: bool,
    comment: &'a str,
}

fn parse_row(line: &str) -> Row<'_> {
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
    Row {
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

#[test]
fn bip340_official() {
    let mut rows = VECTORS.lines();
    let header = rows.next().expect("csv header");
    assert!(
        header.starts_with("index,secret key,public key,"),
        "unexpected BIP-340 csv header: {header}"
    );
    let all: Vec<Row<'_>> = rows
        .filter(|line| !line.is_empty())
        .map(parse_row)
        .collect();
    // Nostr keys/signatures are 32/64-byte fixed: other message sizes
    // cannot be expressed.
    let rows: Vec<&Row<'_>> = all.iter().filter(|r| r.message.len() == 32).collect();
    let skipped = all.len() - rows.len();
    let mut signed_rows = 0_u32;
    for row in &rows {
        let id = EventId::from_slice(&row.message).expect("32-byte message");
        let pubkey = PublicKey::from_slice(&row.pubkey).expect("32-byte pubkey");
        let signature = Signature::from_slice(&row.signature).expect("64-byte signature");

        if !row.secret_key.is_empty() {
            // Signing rows also pin secret -> public derivation.
            let keys = Keys::new(SecretKey::from_hex(row.secret_key).expect("vector scalar"));
            assert_eq!(
                keys.public_key().as_bytes().as_slice(),
                row.pubkey.as_slice(),
                "vector {}: derived public key",
                row.index
            );
            let aux = unhex_arr::<32>(row.aux_rand).expect("aux hex");
            let signed = keys.sign_id(&id, &mut AuxRng(aux)).unwrap();
            assert_eq!(
                signed.as_bytes().as_slice(),
                row.signature.as_slice(),
                "vector {}: signature",
                row.index
            );
            signed_rows += 1;
        }

        let verifies = signature.verify(&id, &pubkey).is_ok();
        assert_eq!(
            verifies, row.expected,
            "vector {}: {}",
            row.index, row.comment
        );
    }
    assert!(signed_rows > 0, "no BIP-340 signing rows ran");
    assert_eq!(rows.len(), 15, "executed row count changed");
    assert_eq!(skipped, 4, "skipped row count changed");
}
