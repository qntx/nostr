//! Differential replay of the TS parity streams against `nk-core`.
//!
//! `bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out <dir>`
//! writes one JSONL file per capability (a `{"capability","seed","count"}` meta
//! line, then `{"i","input","out"|"err","nonCanonicalJson"?}` records). These
//! `#[ignore]` tests replay every input through `nk-core` and require exact
//! equality — zero divergence. `NK_DIFF_DIR` unset or empty fails.
//!
//!   NK_DIFF_DIR=$PWD/target/parity cargo test -p nk-core --all-features \
//!       --test it -- --ignored diff

use std::path::PathBuf;

use nk_core::nips::nip10::{Quote, ThreadReferences};
use nk_core::nips::nip19::{AddressPointer, Entity, EventPointer, ProfilePointer};
use nk_core::nips::nip27::{ContentBlock, ParseOptions, Reference, parse_content};
use nk_core::nips::nip46::{BunkerUri, NostrConnectUri};
use nk_core::{ClientMessage, Event, Filter, PublicKey, RelayMessage, Tag, Tags, UnsignedEvent};

use serde::Deserialize;
use serde_json::{Value, json};

use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(Deserialize)]
struct Meta {
    capability: String,
    #[expect(dead_code, reason = "kept for debugging")]
    seed: u64,
}

#[derive(Deserialize)]
struct Case {
    i: u64,
    input: String,
    out: Option<Value>,
    #[serde(default, rename = "nonCanonicalJson")]
    non_canonical: bool,
}

fn diff_dir() -> PathBuf {
    let dir = std::env::var("NK_DIFF_DIR").expect(
        "NK_DIFF_DIR is not set — generate cases with \
         `bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out <dir>`",
    );
    assert!(!dir.is_empty(), "NK_DIFF_DIR must not be empty");
    PathBuf::from(dir)
}

fn load(capability: &str) -> Vec<Case> {
    let path = diff_dir().join(format!("{capability}.jsonl"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{capability}: cannot read {}: {error}", path.display()));
    let mut lines = text.lines();
    let meta: Meta = serde_json::from_str(lines.next().unwrap_or_default())
        .unwrap_or_else(|e| panic!("{capability}: bad meta line: {e}"));
    assert_eq!(meta.capability, capability);
    let cases: Vec<Case> = lines
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{capability}: bad case {line:?}: {e}"))
        })
        .collect();
    assert!(!cases.is_empty(), "{capability}: no cases");
    cases
}

/// `run` returns `Ok(got)` on acceptance or `Err(())` on rejection. On
/// mismatch it reports up to ten records and panics — zero divergence.
fn replay<F>(capability: &str, run: F)
where
    F: Fn(&str) -> Result<Value, ()>,
{
    let cases = load(capability);
    let mut samples: Vec<String> = Vec::new();
    let mut mismatches = 0usize;
    for case in &cases {
        // Records flagged non-canonical must be rejected regardless of the
        // TS outcome — `JSON.parse` accepted them, the wire profile does not.
        if case.non_canonical {
            // Records flagged non-canonical must be rejected regardless of
            // the TS outcome — `JSON.parse` accepted them, the wire profile
            // does not.
            if run(&case.input).is_ok() {
                mismatches += 1;
                if samples.len() < 10 {
                    samples.push(format!(
                        "  i={}: input={:?}\n    must-reject (nonCanonicalJson)",
                        case.i, case.input
                    ));
                }
            }
            continue;
        }
        let got = run(&case.input).ok();
        let want = case.out.clone();
        if got != want {
            mismatches += 1;
            if samples.len() < 10 {
                samples.push(format!(
                    "  i={}: input={:?}\n    got:  {}\n    want: {}",
                    case.i,
                    case.input,
                    got.as_ref()
                        .map_or("<err>".to_string(), ToString::to_string),
                    want.as_ref()
                        .map_or("<err>".to_string(), ToString::to_string),
                ));
            }
        }
    }
    assert_eq!(
        mismatches,
        0,
        "{capability}: {mismatches} mismatches\n{}",
        samples.join("\n")
    );
}

fn str_out(s: String) -> Result<Value, ()> {
    Ok(Value::String(s))
}

fn tags_from(input: &Value) -> Result<Tags, ()> {
    let raw = input["tags"].as_array().ok_or(())?;
    let mut tags = Tags::new();
    for t in raw {
        let arr = t.as_array().ok_or(())?;
        // TS `parseThreadTags` only inspects `e`/`q`/`p` tags and throws when
        // an accessed member is not a string; other tags are skipped whole.
        let strict = matches!(arr.first().and_then(Value::as_str), Some("e" | "q" | "p"));
        let mut items: Vec<String> = Vec::with_capacity(arr.len());
        let mut clean = true;
        for x in arr {
            match x.as_str() {
                Some(v) => items.push(v.to_owned()),
                None if strict => return Err(()),
                None => clean = false,
            }
        }
        if !clean {
            continue;
        }
        if let Ok(tag) = Tag::new(items) {
            tags.push(tag);
        }
    }
    Ok(tags)
}

/// Extracts the raw JSON text of a top-level `"key": <value>` member —
/// strings-escape-aware, so embedded duplicate keys survive to the strict
/// sub-parsers (a `serde_json::Value` round-trip would drop them).
fn raw_member<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    let bytes = input.as_bytes();
    let needle = format!("\"{key}\"");
    let mut at = 0usize;
    while let Some(off) = input[at..].find(&needle) {
        let key_at = at + off;
        // Skip strings before the match — the needle could sit inside one.
        let mut i = key_at + needle.len();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            at = key_at + needle.len();
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        // Scan a JSON value, tracking braces and strings.
        let mut depth = 0usize;
        let mut in_str = false;
        let mut esc = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_str {
                if esc {
                    esc = false;
                } else if b == b'\\' {
                    esc = true;
                } else if b == b'"' {
                    in_str = false;
                }
            } else if b == b'"' {
                in_str = true;
            } else if b == b'{' || b == b'[' {
                depth += 1;
            } else if b == b'}' || b == b']' {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some(&input[start..=i]);
                }
            } else if depth == 0 && matches!(b, b',' | b'}' | b' ' | b'\t' | b'\n' | b'\r') {
                return Some(&input[start..i]);
            }
            i += 1;
        }
        if depth == 0 {
            return Some(&input[start..]);
        }
        return None;
    }
    None
}

// ── projections ─────────────────────────────────────────────────────────────

fn event_pointer_json(p: &EventPointer) -> Value {
    json!({
        "id": p.id.to_hex(),
        "relays": p.relays,
        "author": p.author.map(|a| a.to_hex()),
        "kind": p.kind.map(|k| u64::from(k.as_u16())),
    })
}

fn profile_pointer_json(p: &ProfilePointer) -> Value {
    json!({"pubkey": p.pubkey.to_hex(), "relays": p.relays})
}

fn address_pointer_json(p: &AddressPointer) -> Value {
    json!({
        "type": "address",
        "identifier": p.identifier,
        "pubkey": p.pubkey.to_hex(),
        "kind": u64::from(p.kind.as_u16()),
        "relays": p.relays,
    })
}

fn entity_json(e: &Entity) -> Value {
    match e {
        Entity::Profile(p) => {
            json!({"type": "nprofile", "pubkey": p.pubkey.to_hex(), "relays": p.relays})
        }
        Entity::Event(p) => {
            let mut v = json!({"type": "nevent", "id": p.id.to_hex(), "relays": p.relays});
            if let Some(a) = p.author {
                v["author"] = json!(a.to_hex());
            }
            if let Some(k) = p.kind {
                v["kind"] = json!(u64::from(k.as_u16()));
            }
            v
        }
        Entity::Address(p) => json!({
            "type": "naddr", "identifier": p.identifier, "pubkey": p.pubkey.to_hex(),
            "kind": u64::from(p.kind.as_u16()), "relays": p.relays,
        }),
        Entity::Secret(s) => {
            json!({"type": "nsec", "secret": s.with_secret_bytes(|b| crate::common::hex_str(b))})
        }
        Entity::Public(p) => json!({"type": "npub", "pubkey": p.to_hex()}),
        Entity::Note(id) => json!({"type": "note", "id": id.to_hex()}),
        _ => unreachable!("non-exhaustive"),
    }
}

fn reference_json(r: &Reference) -> Value {
    match r {
        Reference::Profile(p) => json!({
            "type": "profile", "pubkey": p.pubkey.to_hex(), "relays": p.relays,
        }),
        Reference::Event(p) => {
            let mut v = json!({"type": "event", "id": p.id.to_hex(), "relays": p.relays});
            v["author"] = p.author.map_or(Value::Null, |a| json!(a.to_hex()));
            v["kind"] = p.kind.map_or(Value::Null, |k| json!(u64::from(k.as_u16())));
            v
        }
        Reference::Address(p) => json!({
            "type": "address", "identifier": p.identifier, "pubkey": p.pubkey.to_hex(),
            "kind": u64::from(p.kind.as_u16()), "relays": p.relays,
        }),
    }
}

fn block_json(b: &ContentBlock<'_>) -> Value {
    match b {
        ContentBlock::Text(t) => json!({"type": "text", "text": t}),
        ContentBlock::Reference { reference, bare } => json!({
            "type": "reference", "bare": bare, "pointer": reference_json(reference),
        }),
        ContentBlock::Url(u) => json!({"type": "url", "url": u}),
        ContentBlock::Image(u) => json!({"type": "image", "url": u}),
        ContentBlock::Video(u) => json!({"type": "video", "url": u}),
        ContentBlock::Audio(u) => json!({"type": "audio", "url": u}),
        ContentBlock::Relay(u) => json!({"type": "relay", "url": u}),
        ContentBlock::Hashtag(t) => json!({"type": "hashtag", "value": t}),
        ContentBlock::Emoji { shortcode, url } => {
            json!({"type": "emoji", "shortcode": shortcode, "url": url})
        }
        ContentBlock::Invoice(s) => json!({"type": "invoice", "bolt11": s}),
        _ => unreachable!("non-exhaustive"),
    }
}

// ── capabilities ────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_event_serialize() {
    replay("core.event.serialize", |input| {
        str_out(
            UnsignedEvent::from_json(input)
                .map_err(|_| ())?
                .id_preimage(),
        )
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_event_id() {
    replay("core.event.id", |input| {
        str_out(
            UnsignedEvent::from_json(input)
                .map_err(|_| ())?
                .id()
                .to_hex(),
        )
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_filter_match() {
    replay("core.filter.match", |input| {
        let f_raw = raw_member(input, "filter").ok_or(())?;
        let e_raw = raw_member(input, "event").ok_or(())?;
        let filter = Filter::from_json(f_raw).map_err(|_| ())?;
        let event = Event::from_json(e_raw).map_err(|_| ())?;
        Ok(Value::Bool(filter.matches(&event)))
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_filter_canonicalize() {
    replay("core.filter.canonicalize", |input| {
        let filter = Filter::from_json(input).map_err(|_| ())?;
        str_out(filter.to_json())
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_message_client() {
    replay("core.message.client", |input| {
        str_out(ClientMessage::from_json(input).map_err(|_| ())?.to_json())
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_message_relay() {
    replay("core.message.relay", |input| {
        str_out(RelayMessage::from_json(input).map_err(|_| ())?.to_json())
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_nip10_thread() {
    replay("nip10.thread", |input| {
        let v: Value = serde_json::from_str(input).map_err(|_| ())?;
        let tags = tags_from(&v)?;
        let t = ThreadReferences::from(&tags);
        Ok(json!({
            "root": t.root.as_ref().map_or(Value::Null, |p| event_pointer_json(p)),
            "reply": t.reply.as_ref().map_or(Value::Null, |p| event_pointer_json(p)),
            "mentions": t.mentions.iter().map(event_pointer_json).collect::<Vec<_>>(),
            "quotes": t.quotes.iter().map(|q| match q {
                Quote::Event(p) => {
                    let mut v = event_pointer_json(p);
                    v["type"] = json!("event");
                    v
                }
                Quote::Address(p) => address_pointer_json(p),
            }).collect::<Vec<_>>(),
            "profiles": t.profiles.iter().map(profile_pointer_json).collect::<Vec<_>>(),
        }))
    });
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_nip19_codec() {
    replay("nip19.codec", |input| {
        let v: Value = serde_json::from_str(input).map_err(|_| ())?;
        if v["op"].as_str() == Some("encode") {
            let e = entity_from(&v["entity"]).ok_or(())?;
            return str_out(e.to_bech32().map_err(|_| ())?);
        }
        let entity = Entity::from_bech32(v["input"].as_str().ok_or(())?).map_err(|_| ())?;
        Ok(entity_json(&entity))
    });
}

fn entity_from(v: &Value) -> Option<Entity> {
    Some(match v["type"].as_str()? {
        "npub" => Entity::Public(PublicKey::from_hex(v["pubkey"].as_str()?).ok()?),
        "note" => Entity::Note(nk_core::EventId::from_hex(v["id"].as_str()?).ok()?),
        "nsec" => Entity::Secret(nk_core::SecretKey::from_hex(v["secret"].as_str()?).ok()?),
        "nprofile" => Entity::Profile(ProfilePointer {
            pubkey: PublicKey::from_hex(v["pubkey"].as_str()?).ok()?,
            relays: v["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        }),
        "nevent" => Entity::Event(EventPointer {
            id: nk_core::EventId::from_hex(v["id"].as_str()?).ok()?,
            relays: v["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            author: match v.get("author") {
                Some(a) if !a.is_null() => {
                    let s = a.as_str()?;
                    if s.is_empty() {
                        None
                    } else {
                        Some(PublicKey::from_hex(s).ok()?)
                    }
                }
                _ => None,
            },
            kind: match v.get("kind") {
                Some(k) if !k.is_null() => {
                    Some(nk_core::Kind::new(u16::try_from(k.as_u64()?).ok()?))
                }
                _ => None,
            },
        }),
        "naddr" => Entity::Address(AddressPointer {
            identifier: v["identifier"].as_str()?.to_owned(),
            pubkey: PublicKey::from_hex(v["pubkey"].as_str()?).ok()?,
            kind: nk_core::Kind::new(u16::try_from(v["kind"].as_u64()?).ok()?),
            relays: v["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        }),
        _ => return None,
    })
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_nip27_tokenize() {
    replay("nip27.tokenize", |input| {
        let v: Value = serde_json::from_str(input).map_err(|_| ())?;
        let content = v["content"].as_str().ok_or(())?;
        let tags = if v.get("tags").is_some() {
            Some(tags_from(&v)?)
        } else {
            None
        };
        let imeta: Option<BTreeMap<String, String>> = v.get("imeta").and_then(|m| {
            m.as_object().map(|o| {
                o.iter()
                    .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
        });
        let options = ParseOptions {
            legacy_bech32: v["legacy"].as_bool().unwrap_or(false),
            imeta: imeta.as_ref(),
        };
        let blocks = parse_content(content, tags.as_ref(), options);
        Ok(Value::Array(blocks.iter().map(block_json).collect()))
    });
}

fn empty_absent(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

#[test]
#[ignore = "requires NK_DIFF_DIR"]
fn diff_nip46_uri() {
    replay("nip46.uri", |input| {
        let v: Value = serde_json::from_str(input).map_err(|_| ())?;
        let relays: Vec<String> = v["relays"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(client) = v.get("client").and_then(Value::as_str) {
            let pk = PublicKey::from_hex(client).map_err(|_| ())?;
            let mut uri = NostrConnectUri::new(
                pk,
                relays.clone(),
                v["secret"].as_str().unwrap_or("").to_owned(),
            )
            .map_err(|_| ())?;
            let perms: Vec<String> = v["perms"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            uri = uri.with_perms(perms);
            if let Some(x) = v.get("name").and_then(Value::as_str) {
                uri = uri.with_name(x);
            }
            if let Some(x) = v.get("url").and_then(Value::as_str) {
                uri = uri.with_url(x);
            }
            if let Some(x) = v.get("image").and_then(Value::as_str) {
                uri = uri.with_image(x);
            }
            let uri_str = uri.to_string();
            let parsed = NostrConnectUri::from_str(&uri_str).map_err(|_| ())?;
            // Mirror the TS round-trip checks.
            let name = v.get("name").and_then(Value::as_str);
            let url = v.get("url").and_then(Value::as_str);
            let image = v.get("image").and_then(Value::as_str);
            let want_perms: Vec<String> = v["perms"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            if parsed.client().to_hex() != client.to_lowercase()
                || parsed.secret() != v["secret"].as_str().unwrap_or("")
                || parsed.relays() != relays.as_slice()
                || parsed.perms() != want_perms.as_slice()
                || parsed.name().map(str::to_owned) != empty_absent(name.map(str::to_owned))
                || parsed.url().map(str::to_owned) != empty_absent(url.map(str::to_owned))
                || parsed.image().map(str::to_owned) != empty_absent(image.map(str::to_owned))
            {
                return Err(());
            }
            return Ok(json!({
                "uri": uri_str,
                "parsed": {
                    "clientPubkey": parsed.client().to_hex(),
                    "relays": parsed.relays(),
                    "secret": parsed.secret(),
                    "perms": parsed.perms(),
                    "name": parsed.name(),
                    "url": parsed.url(),
                    "image": parsed.image(),
                },
            }));
        }
        let pubkey_s = v["pubkey"].as_str().unwrap_or("");
        let pk = PublicKey::from_hex(pubkey_s).map_err(|_| ())?;
        let secret = v["secret"].as_str().map(str::to_owned);
        let uri = BunkerUri {
            remote_signer: pk,
            relays: relays.clone(),
            secret: secret.clone(),
        };
        let uri_str = uri.to_string();
        let parsed = BunkerUri::from_str(&uri_str).map_err(|_| ())?;
        if parsed.remote_signer.to_hex() != pubkey_s.to_lowercase()
            || parsed.relays != relays
            || parsed.secret != empty_absent(secret)
        {
            return Err(());
        }
        Ok(json!({
            "uri": uri_str,
            "parsed": {
                "pubkey": parsed.remote_signer.to_hex(),
                "relays": parsed.relays,
                "secret": parsed.secret,
            },
        }))
    });
}
