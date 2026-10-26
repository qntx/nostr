#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::nips::nip44::ConversationKey;
use nk_core::{PublicKey, SecretKey};

// A fixed conversation key: decrypt must be total — every input either
// decrypts or errors, never panics.
const KEY: [u8; 32] = [0x42; 32];
const PEER: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

fuzz_target!(|data: &str| {
    if let (Ok(secret), Ok(peer)) = (SecretKey::from_bytes(KEY), PublicKey::from_hex(PEER))
        && let Ok(conversation) = ConversationKey::derive(&secret, &peer)
    {
        let _ = conversation.decrypt(data);
    }
});
