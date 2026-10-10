//! Executes `vectors/bip340/official.csv` against the `nk` public API:
//! signing rows through `Keys::sign_id_with_aux`, verification rows through
//! `Signature::verify`, and public-key derivation through
//! `SecretKey::public_key`.

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

use nk::{EventId, Keys, PublicKey, SecretKey, Signature};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/bip340/official.csv"
));

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    assert!(
        bytes.len().is_multiple_of(2),
        "hex length must be even, got {} for {input}",
        bytes.len()
    );
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for &[hi, lo] in bytes.as_chunks::<2>().0 {
        let hi = hex_nibble(hi).expect("hex digit");
        let lo = hex_nibble(lo).expect("hex digit");
        out.push((hi << 4) | lo);
    }
    out
}

fn decode_hex_array<const N: usize>(input: &str) -> [u8; N] {
    let bytes = decode_hex(input);
    <[u8; N]>::try_from(bytes.as_slice()).expect("expected fixed-length hex")
}

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

fn parse_row(line: &str) -> Vector<'_> {
    let mut fields = line.splitn(8, ',');
    let index = fields.next().expect("index");
    let secret_key = fields.next().expect("secret key");
    let pubkey = decode_hex(fields.next().expect("public key"));
    let aux_rand = fields.next().expect("aux_rand");
    let message = decode_hex(fields.next().expect("message"));
    let signature = decode_hex(fields.next().expect("signature"));
    let result = fields.next().expect("verification result");
    let comment = fields.next().unwrap_or("");
    assert!(
        result == "TRUE" || result == "FALSE",
        "vector {index}: unknown result {result}"
    );
    let expected = result == "TRUE";
    Vector {
        index,
        secret_key,
        aux_rand,
        pubkey,
        message,
        signature,
        expected,
        comment,
    }
}

/// nostr signs 32-byte event ids only — rows with other message sizes cannot
/// be expressed as an `EventId` and are skipped.
const fn is_event_id_sized(row: &Vector<'_>) -> bool {
    row.message.len() == 32
}

#[test]
fn bip340_official() {
    let all = parse_vectors(VECTORS);
    let rows: Vec<&Vector<'_>> = all.iter().filter(|row| is_event_id_sized(row)).collect();
    let skipped = all.len() - rows.len();
    let mut signed_rows = 0_u32;
    for row in &rows {
        let Ok(message) = <[u8; 32]>::try_from(row.message.as_slice()) else {
            panic!("vector {}: filtered row has non-32-byte message", row.index);
        };
        let id = EventId::from_bytes(message);
        let pubkey = PublicKey::from_slice(&row.pubkey).expect("vector pubkey is 32 bytes");
        let signature =
            Signature::from_slice(&row.signature).expect("vector signature is 64 bytes");

        if !row.secret_key.is_empty() {
            // Signing rows also pin secret -> public derivation.
            let keys = Keys::new(
                SecretKey::from_hex(row.secret_key).expect("vector secret key is a scalar"),
            );
            assert_eq!(
                keys.public_key().as_bytes().as_slice(),
                row.pubkey.as_slice(),
                "vector {}: derived public key",
                row.index
            );
            let aux: [u8; 32] = decode_hex_array(row.aux_rand);
            let signed = keys.sign_id_with_aux(&id, &aux);
            assert_eq!(
                signed.as_bytes(),
                row.signature.as_slice(),
                "vector {}: signature",
                row.index
            );
            signed_rows += 1;
        }

        assert_eq!(
            signature.verify(&id, &pubkey).is_ok(),
            row.expected,
            "vector {}: {}",
            row.index,
            row.comment
        );
    }
    assert!(
        signed_rows > 0,
        "no BIP-340 signing rows ran for vectors/bip340/official.csv"
    );
    assert_eq!(
        rows.len() + skipped,
        all.len(),
        "executed + skipped must equal total rows"
    );
    // 15 verification rows execute; rows 15-18 (message sizes 0, 1, 17, 100)
    // are skipped by is_event_id_sized. Both counts are pinned so the skip set
    // cannot grow silently.
    assert_eq!(rows.len(), 15, "executed row count changed");
    assert_eq!(skipped, 4, "skipped row count changed");
}
