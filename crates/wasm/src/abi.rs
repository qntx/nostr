//! The `nostr_*` byte ABI (version 2) exported by `nostr_wasm.wasm` — the sole
//! `unsafe` site in the workspace (NK-ADR-014).
//!
//! Specification: `docs/nk/acceleration.mdx`, "字节 ABI 规格（版本 1）".
//!
//! - Status codes: `0` ok / verification passed, `1` verification failed, `2`
//!   invalid input (null pointer, invalid scalar, or a non-point public key).
//! - No function panics; every fallible path returns a status code.
//! - The operation functions only touch caller-provided pointers and hold no
//!   state, so they compile unchanged into a native static library.
//! - `nostr_buffer` exists only on `wasm32`: a per-instance growable scratch
//!   region, the documented exception to "no global mutable state".

#![allow(
    unsafe_code,
    reason = "the byte ABI dereferences caller-provided pointers"
)]

use secp256k1::schnorr::{Signature as SchnorrSignature, sign_with_aux_rand, verify};
use secp256k1::{Keypair, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// Status: success, or the signature verified.
const OK: i32 = 0;
/// Status: the hash or signature check failed.
const VERIFY_FAILED: i32 = 1;
/// Status: invalid input (null pointer, out-of-range scalar, non-point key).
const INVALID_INPUT: i32 = 2;

/// The ABI version this build implements.
#[unsafe(no_mangle)]
pub const extern "C" fn nostr_abi_version() -> u32 {
    2
}

/// Reads exactly `N` bytes at `ptr`; `None` on a null pointer.
///
/// Callers uphold the ABI contract: `ptr` names `N` readable bytes.
fn read<const N: usize>(ptr: *const u8) -> Option<[u8; N]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` is non-null and the caller contract grants N readable
    // bytes. `[u8; N]` has alignment 1, so no alignment check applies.
    Some(unsafe { ptr.cast::<[u8; N]>().read() })
}

/// Copies the caller's 32 secret bytes and zeroes the caller's region, so no
/// path — valid scalar or not — leaves secret material in shared memory.
#[allow(
    clippy::missing_const_for_fn,
    reason = "the body performs raw-pointer copies, which are not const"
)]
fn take_secret(seckey: *mut u8) -> Option<[u8; 32]> {
    if seckey.is_null() {
        return None;
    }
    let mut bytes = [0u8; 32];
    // SAFETY: `seckey` is non-null and the caller contract grants 32 readable
    // bytes.
    unsafe { core::ptr::copy_nonoverlapping(seckey, bytes.as_mut_ptr(), 32) };
    // SAFETY: same region, writable — the zeroing store is observable to the
    // caller after return, so it cannot be elided.
    unsafe { core::ptr::write_bytes(seckey, 0, 32) };
    Some(bytes)
}

/// BIP-340 verification status: `verify_schnorr` merges "not a point" and
/// "bad signature" into one error, so the cold error path re-checks the point
/// directly to split [`INVALID_INPUT`] from [`VERIFY_FAILED`].
fn verify_status(id: [u8; 32], pubkey: [u8; 32], sig: [u8; 64]) -> i32 {
    let signature = SchnorrSignature::from_byte_array(sig);
    let Ok(public_key) = XOnlyPublicKey::from_byte_array(pubkey) else {
        return INVALID_INPUT;
    };
    match verify(&signature, &id, &public_key) {
        Ok(()) => OK,
        Err(_) => VERIFY_FAILED,
    }
}

/// `nostr_verify(id, pubkey, sig)` — BIP-340 verify of the 32-byte `id`.
///
/// # Safety
///
/// The caller contract grants fixed-size readable regions: `id` 32 bytes,
/// `pubkey` 32 bytes, `sig` 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_verify(id: *const u8, pubkey: *const u8, sig: *const u8) -> i32 {
    let (Some(id), Some(pubkey), Some(sig)) = (read::<32>(id), read::<32>(pubkey), read::<64>(sig))
    else {
        return INVALID_INPUT;
    };
    verify_status(id, pubkey, sig)
}

/// `nostr_verify_serialized(ser, ser_len, id, pubkey, sig)` — `sha256(ser)`
/// must equal `id`, then BIP-340 verify.
///
/// # Safety
///
/// The caller contract grants `ser_len` readable bytes at `ser` plus the
/// fixed-size regions of [`nostr_verify`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_verify_serialized(
    serialized: *const u8,
    serialized_len: u32,
    id: *const u8,
    pubkey: *const u8,
    sig: *const u8,
) -> i32 {
    let (Some(id), Some(pubkey), Some(sig)) = (read::<32>(id), read::<32>(pubkey), read::<64>(sig))
    else {
        return INVALID_INPUT;
    };
    if serialized.is_null() {
        return INVALID_INPUT;
    }
    // SAFETY: `serialized` is non-null and the caller contract grants
    // `serialized_len` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(serialized, serialized_len as usize) };
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != id {
        return VERIFY_FAILED;
    }
    verify_status(id, pubkey, sig)
}

/// `nostr_sign(id, seckey, aux, out_sig)` — BIP-340 sign the 32-byte `id`
/// with caller-supplied auxiliary randomness; writes 64 signature bytes on
/// `0`.
///
/// The caller's `seckey` region is zeroed before this function returns on
/// every path (a null `seckey` cannot be wiped and counts as invalid input).
///
/// # Safety
///
/// The caller contract grants: `id`/`aux` 32 readable bytes each, `seckey` 32
/// readable+writable bytes, `out_sig` 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_sign(
    id: *const u8,
    seckey: *mut u8,
    aux: *const u8,
    out_sig: *mut u8,
) -> i32 {
    let Some(secret_bytes) = take_secret(seckey) else {
        return INVALID_INPUT;
    };
    let Ok(mut secret) = secp256k1::SecretKey::from_secret_bytes(secret_bytes) else {
        return INVALID_INPUT;
    };
    let (Some(id), Some(aux)) = (read::<32>(id), read::<32>(aux)) else {
        secret.non_secure_erase();
        return INVALID_INPUT;
    };
    if out_sig.is_null() {
        secret.non_secure_erase();
        return INVALID_INPUT;
    }
    let keypair = Keypair::from_secret_key(&secret);
    secret.non_secure_erase();
    let signature = sign_with_aux_rand(&id, &keypair, &aux);
    // SAFETY: `out_sig` is non-null and the caller contract grants 64
    // writable bytes; the regions do not overlap (all inputs already read).
    unsafe { out_sig.cast::<[u8; 64]>().write(signature.to_byte_array()) };
    OK
}

/// `nostr_public_key(seckey, out_pubkey)` — x-only public key for `seckey`;
/// writes 32 bytes on `0`. Zeroes the caller's `seckey` region like
/// [`nostr_sign`].
///
/// # Safety
///
/// The caller contract grants `seckey` 32 readable+writable bytes and
/// `out_pubkey` 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_public_key(seckey: *mut u8, out_pubkey: *mut u8) -> i32 {
    let Some(secret_bytes) = take_secret(seckey) else {
        return INVALID_INPUT;
    };
    let Ok(mut secret) = secp256k1::SecretKey::from_secret_bytes(secret_bytes) else {
        return INVALID_INPUT;
    };
    if out_pubkey.is_null() {
        secret.non_secure_erase();
        return INVALID_INPUT;
    }
    let (public_key, _) = secret.x_only_public_key();
    secret.non_secure_erase();
    // SAFETY: `out_pubkey` is non-null and the caller contract grants 32
    // writable bytes.
    unsafe {
        out_pubkey
            .cast::<[u8; 32]>()
            .write(public_key.to_byte_array());
    }
    OK
}

/// Per-instance scratch region backing `nostr_buffer`: the single documented
/// exception to "no global mutable state", sound because a
/// `wasm32-unknown-unknown` instance is single-threaded.
#[cfg(target_arch = "wasm32")]
struct Scratch(core::cell::UnsafeCell<Vec<u8>>);

// SAFETY: `wasm32-unknown-unknown` runs single-threaded and the atomics
// target feature is rejected below, so no two threads can observe SCRATCH.
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for Scratch {}

#[cfg(target_arch = "wasm32")]
static SCRATCH: Scratch = Scratch(core::cell::UnsafeCell::new(Vec::new()));

#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
compile_error!(
    "nostr_buffer's shared scratch region requires a single-threaded wasm32 build (no atomics target feature)"
);

/// `nostr_buffer(len)` — grows the scratch region to at least `len` bytes (at
/// most once per call) and returns its start. The address is valid until the
/// next `nostr_buffer` call.
///
/// # Safety
///
/// Callable only on single-threaded wasm32 instances; native callers pass
/// their own memory and must not use this export.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_buffer(len: u32) -> *mut u8 {
    // SAFETY: wasm32-unknown-unknown is single-threaded (atomics rejected at
    // compile time), so this is the only live reference into SCRATCH.
    let buf = unsafe { &mut *SCRATCH.0.get() };
    if buf.len() < len as usize {
        buf.resize(len as usize, 0);
    }
    buf.as_mut_ptr()
}
