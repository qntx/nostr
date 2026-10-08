//! Native tests for the `nk_*` byte ABI: every export is called through raw
//! pointers over `Vec`-backed memory, the same contract wasm callers uphold.

#![allow(unsafe_code, reason = "tests exercise the raw-pointer byte ABI")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests fail by panicking"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

use nk_core::UnsignedEvent;
use nk_wasm::abi::{nk_abi_version, nk_public_key, nk_sign, nk_verify, nk_verify_serialized};

const OK: i32 = 0;
const VERIFY_FAILED: i32 = 1;
const INVALID_INPUT: i32 = 2;

/// BIP-340 official vector 0.
const SK: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
const PK: [u8; 32] = [
    0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
    0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9,
];
const MSG: [u8; 32] = [0; 32];
const AUX: [u8; 32] = [0; 32];
const SIG: [u8; 64] = [
    0xE9, 0x07, 0x83, 0x1F, 0x80, 0x84, 0x8D, 0x10, 0x69, 0xA5, 0x37, 0x1B, 0x40, 0x24, 0x10, 0x36,
    0x4B, 0xDF, 0x1C, 0x5F, 0x83, 0x07, 0xB0, 0x08, 0x4C, 0x55, 0xF1, 0xCE, 0x2D, 0xCA, 0x82, 0x15,
    0x25, 0xF6, 0x6A, 0x4A, 0x85, 0xEA, 0x8B, 0x71, 0xE4, 0x82, 0xA7, 0x4F, 0x38, 0x2D, 0x2C, 0xE5,
    0xEB, 0xEE, 0xE8, 0xFD, 0xB2, 0x17, 0x2F, 0x47, 0x7D, 0xF4, 0x90, 0x0D, 0x31, 0x05, 0x36, 0xC0,
];
/// `x = p + 1`-style bytes: not a field element, so never a curve point.
const BAD_POINT: [u8; 32] = [0xFF; 32];

fn verify(id: &[u8; 32], pubkey: &[u8; 32], sig: &[u8; 64]) -> i32 {
    // SAFETY: fixed-size array references uphold the ABI's pointer contract.
    unsafe { nk_verify(id.as_ptr(), pubkey.as_ptr(), sig.as_ptr()) }
}

fn verify_serialized(ser: &[u8], id: &[u8; 32], pubkey: &[u8; 32], sig: &[u8; 64]) -> i32 {
    // SAFETY: the slices uphold the ABI's pointer contract.
    unsafe {
        nk_verify_serialized(
            ser.as_ptr(),
            u32::try_from(ser.len()).expect("test inputs fit u32"),
            id.as_ptr(),
            pubkey.as_ptr(),
            sig.as_ptr(),
        )
    }
}

fn sign(id: &[u8; 32], seckey: &mut [u8; 32], aux: &[u8; 32], out: &mut [u8; 64]) -> i32 {
    // SAFETY: the slices uphold the ABI's pointer contract.
    unsafe {
        nk_sign(
            id.as_ptr(),
            seckey.as_mut_ptr(),
            aux.as_ptr(),
            out.as_mut_ptr(),
        )
    }
}

fn public_key(seckey: &mut [u8; 32], out: &mut [u8; 32]) -> i32 {
    // SAFETY: the slices uphold the ABI's pointer contract.
    unsafe { nk_public_key(seckey.as_mut_ptr(), out.as_mut_ptr()) }
}

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
        "hex length must be even for {input}"
    );
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for &[hi, lo] in bytes.as_chunks::<2>().0 {
        out.push((hex_nibble(hi).expect("hex digit") << 4) | hex_nibble(lo).expect("hex digit"));
    }
    out
}

fn fixed<const N: usize>(hex: &str) -> [u8; N] {
    <[u8; N]>::try_from(decode_hex(hex)).expect("hex decodes to N bytes")
}

#[test]
fn abi_version_is_one() {
    assert_eq!(nk_abi_version(), 1);
}

#[test]
fn verify_success_failure_and_invalid_input() {
    assert_eq!(verify(&MSG, &PK, &SIG), OK);
    let mut bad_sig = SIG;
    bad_sig[0] ^= 1;
    assert_eq!(verify(&MSG, &PK, &bad_sig), VERIFY_FAILED, "bad signature");
    assert_eq!(verify(&MSG, &BAD_POINT, &SIG), INVALID_INPUT, "bad pubkey");
    // SAFETY: exercised deliberately — null pointers report invalid input.
    let status = unsafe { nk_verify(core::ptr::null(), PK.as_ptr(), SIG.as_ptr()) };
    assert_eq!(status, INVALID_INPUT);
}

#[test]
fn verify_serialized_success_failure_and_invalid_input() {
    let ser = b"[0,\"pk\",1,1,[],\"hello\"]";
    let mut id = [0u8; 32];
    let mut sk = SK;
    let mut sig = [0u8; 64];
    {
        // Sign sha256(ser) with vector 0's key through the ABI.
        let hashed = nk_core::EventId::hash(ser);
        id.copy_from_slice(hashed.as_bytes());
        assert_eq!(sign(&id, &mut sk, &AUX, &mut sig), OK);
    }
    assert_eq!(verify_serialized(ser, &id, &PK, &sig), OK, "valid");

    let mut wrong_id = id;
    wrong_id[0] ^= 1;
    assert_eq!(
        verify_serialized(ser, &wrong_id, &PK, &sig),
        VERIFY_FAILED,
        "hash mismatch"
    );
    let mut tampered = ser.to_vec();
    tampered[1] = b'X';
    assert_eq!(
        verify_serialized(&tampered, &id, &PK, &sig),
        VERIFY_FAILED,
        "tampered serialization"
    );
    assert_eq!(
        verify_serialized(ser, &id, &BAD_POINT, &sig),
        INVALID_INPUT,
        "bad pubkey"
    );
    assert_eq!(
        verify_serialized(&ser[..4], &id, &PK, &sig),
        VERIFY_FAILED,
        "truncated serialized input is a hash mismatch"
    );
    // SAFETY: exercised deliberately — null serialized pointer reports 2.
    let status = unsafe {
        nk_verify_serialized(core::ptr::null(), 5, id.as_ptr(), PK.as_ptr(), sig.as_ptr())
    };
    assert_eq!(status, INVALID_INPUT);
}

#[test]
fn sign_success_and_seckey_wiped() {
    let mut sk = SK;
    let mut out = [0u8; 64];
    assert_eq!(sign(&MSG, &mut sk, &AUX, &mut out), OK);
    assert_eq!(out, SIG, "BIP-340 vector 0 signature");
    assert_eq!(sk, [0u8; 32], "caller seckey wiped");
    assert_eq!(verify(&MSG, &PK, &out), OK);
}

#[test]
fn sign_rejects_invalid_input_and_still_wipes() {
    let mut out = [0u8; 64];
    for mut sk in [[0u8; 32], [0xFF; 32]] {
        assert_eq!(
            sign(&MSG, &mut sk, &AUX, &mut out),
            INVALID_INPUT,
            "out-of-range scalar {sk:?}"
        );
        assert_eq!(sk, [0u8; 32], "caller seckey wiped on failure");
    }
    let mut sk = SK;
    // SAFETY: exercised deliberately — null pointers report 2 and the caller's
    // seckey is still wiped.
    let status = unsafe {
        nk_sign(
            core::ptr::null(),
            sk.as_mut_ptr(),
            AUX.as_ptr(),
            out.as_mut_ptr(),
        )
    };
    assert_eq!(status, INVALID_INPUT);
    assert_eq!(sk, [0u8; 32], "wiped despite null id");
}

#[test]
fn public_key_success_and_seckey_wiped() {
    let mut sk = SK;
    let mut out = [0u8; 32];
    assert_eq!(public_key(&mut sk, &mut out), OK);
    assert_eq!(out, PK, "BIP-340 vector 0 public key");
    assert_eq!(sk, [0u8; 32], "caller seckey wiped");
}

#[test]
fn public_key_rejects_invalid_scalar_and_still_wipes() {
    let mut out = [0u8; 32];
    for mut sk in [[0u8; 32], [0xFF; 32]] {
        assert_eq!(public_key(&mut sk, &mut out), INVALID_INPUT);
        assert_eq!(sk, [0u8; 32], "caller seckey wiped on failure");
    }
}

// Shared-vector coverage through the ABI: the nk-vectors runners assert the
// same files against nk-core; here they drive the raw-pointer surface.

const BIP340_CSV: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/bip340/official.csv"
));
const EVENT_SIGN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-sign.json"
));
const EVENT_SERIALIZE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-serialize.json"
));

#[test]
fn bip340_vectors_through_nk_verify_and_sign() {
    let mut rows = 0u32;
    for line in BIP340_CSV.lines().skip(1).filter(|line| !line.is_empty()) {
        let mut f = line.splitn(8, ',');
        let index = f.next().unwrap_or("?");
        let secret = f.next().expect("secretKey");
        let pubkey = f.next().expect("publicKey");
        let aux = f.next().expect("auxRand");
        let message = f.next().expect("message");
        let signature = f.next().expect("signature");
        let result = f.next().expect("verification result");
        // Same row filter as the nk-vectors runner: 32-byte messages only.
        if message.len() != 64 {
            continue;
        }
        rows += 1;
        let id = fixed::<32>(message);
        let pk = fixed::<32>(pubkey);
        let sig = fixed::<64>(signature);
        let got = verify(&id, &pk, &sig);
        // A FALSE row is either a failed check (1) or a non-point public key
        // reported as invalid input (2); the csv does not distinguish.
        if result == "TRUE" {
            assert_eq!(got, OK, "vector {index} verify");
        } else {
            assert_ne!(got, OK, "vector {index} verify (expected failure)");
        }
        if !secret.is_empty() {
            let mut sk = fixed::<32>(secret);
            let aux = fixed::<32>(aux);
            let mut out_sig = [0u8; 64];
            let mut out_pk = [0u8; 32];
            assert_eq!(
                sign(&id, &mut sk, &aux, &mut out_sig),
                OK,
                "vector {index} sign"
            );
            assert_eq!(out_sig, sig, "vector {index} signature");
            assert_eq!(public_key(&mut fixed::<32>(secret), &mut out_pk), OK);
            assert_eq!(out_pk, pk, "vector {index} public key");
        }
    }
    assert_eq!(rows, 15, "all 32-byte-message rows");
}

#[test]
fn event_sign_vectors_through_abi() {
    let doc: serde_json::Value = serde_json::from_str(EVENT_SIGN).expect("vector json");
    let cases = doc["cases"].as_array().expect("cases array");
    for case in cases {
        let event = &case["event"];
        let id = fixed::<32>(event["id"].as_str().expect("id"));
        let pk = fixed::<32>(event["pubkey"].as_str().expect("pubkey"));
        let sig = fixed::<64>(event["sig"].as_str().expect("sig"));
        assert_eq!(verify(&id, &pk, &sig), OK, "event-sign case");

        let unsigned: UnsignedEvent =
            serde_json::from_value(case["unsigned"].clone()).expect("unsigned event");
        let serialized = unsigned.canonical_json().into_bytes();
        assert_eq!(
            verify_serialized(&serialized, &id, &pk, &sig),
            OK,
            "event-sign case through the serialized path"
        );
    }
}

#[test]
fn event_serialize_vectors_reach_the_hash_check() {
    let doc: serde_json::Value = serde_json::from_str(EVENT_SERIALIZE).expect("vector json");
    let cases = doc["cases"].as_array().expect("cases array");
    // A signature signed over the vector id by a key we control: the hash
    // check passes and the schnorr check succeeds.
    for case in cases {
        let serialized = case["serialized"].as_str().expect("serialized");
        let id = fixed::<32>(case["id"].as_str().expect("id"));
        let mut sig = [0u8; 64];
        let mut sk = SK;
        assert_eq!(sign(&id, &mut sk, &AUX, &mut sig), OK);
        assert_eq!(
            verify_serialized(serialized.as_bytes(), &id, &PK, &sig),
            OK,
            "serialized path accepts vector id"
        );
        let mut wrong = id;
        wrong[0] ^= 1;
        assert_eq!(
            verify_serialized(serialized.as_bytes(), &wrong, &PK, &sig),
            VERIFY_FAILED,
            "mismatched id fails the hash check"
        );
    }
}
