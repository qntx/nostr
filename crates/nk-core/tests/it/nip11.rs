//! vectors/nip11/codec.json — `nip11.codec`.

use nk_core::nips::nip11::{Limitation, RelayInformation};
use nk_core::{PublicKey, RelayUrl};

use serde_json::Value;

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip11/codec.json"
));

fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn opt_pk(v: &Value, key: &str) -> Option<PublicKey> {
    v.get(key)
        .and_then(Value::as_str)
        .map(|s| PublicKey::from_hex(s).unwrap())
}

type NumField = fn(&Limitation) -> Option<u64>;
type BoolField = fn(&Limitation) -> Option<bool>;

fn compare_limitation(name: &str, out: &Value, lim: Option<Limitation>) {
    match out.get("limitation") {
        None | Some(Value::Null) => assert!(lim.is_none(), "{name}"),
        Some(l) => {
            let lim = lim.unwrap();
            let numbers: [(&str, NumField); 10] = [
                ("max_message_length", |l| l.max_message_length),
                ("max_subscriptions", |l| l.max_subscriptions),
                ("max_limit", |l| l.max_limit),
                ("max_subid_length", |l| l.max_subid_length),
                ("max_event_tags", |l| l.max_event_tags),
                ("max_content_length", |l| l.max_content_length),
                ("min_pow_difficulty", |l| l.min_pow_difficulty),
                ("created_at_lower_limit", |l| l.created_at_lower_limit),
                ("created_at_upper_limit", |l| l.created_at_upper_limit),
                ("default_limit", |l| l.default_limit),
            ];
            for (key, field) in numbers {
                assert_eq!(
                    field(&lim),
                    l.get(key).and_then(Value::as_u64),
                    "{name} limitation.{key}"
                );
            }
            let flags: [(&str, BoolField); 3] = [
                ("auth_required", |l| l.auth_required),
                ("payment_required", |l| l.payment_required),
                ("restricted_writes", |l| l.restricted_writes),
            ];
            for (key, field) in flags {
                assert_eq!(
                    field(&lim),
                    l.get(key).and_then(Value::as_bool),
                    "{name} limitation.{key}"
                );
            }
        }
    }
}

#[test]
fn nip11_url() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["url"].as_array().unwrap() {
        let url = RelayUrl::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            RelayInformation::url(&url),
            case["out"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn nip11_document() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["document"].as_array().unwrap() {
        let json = case["json"].as_str().unwrap();
        let out = &case["out"];
        if out.get("err") == Some(&Value::Bool(true)) {
            assert!(
                RelayInformation::from_json(json).is_err(),
                "{}",
                case["name"]
            );
            continue;
        }
        let info = RelayInformation::from_json(json).unwrap();
        let name = case["name"].as_str().unwrap();
        assert_eq!(info.name, opt_str(out, "name"), "{name}");
        assert_eq!(info.description, opt_str(out, "description"), "{name}");
        assert_eq!(info.banner, opt_str(out, "banner"), "{name}");
        assert_eq!(info.icon, opt_str(out, "icon"), "{name}");
        assert_eq!(info.pubkey, opt_pk(out, "pubkey"), "{name}");
        assert_eq!(info.self_pubkey, opt_pk(out, "self"), "{name}");
        assert_eq!(info.contact, opt_str(out, "contact"), "{name}");
        let want_nips: Option<Vec<u64>> = out
            .get("supported_nips")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().map(Value::as_u64).collect());
        assert_eq!(info.supported_nips, want_nips, "{name}");
        assert_eq!(info.software, opt_str(out, "software"), "{name}");
        assert_eq!(info.version, opt_str(out, "version"), "{name}");
        compare_limitation(name, out, info.limitation);
        assert_eq!(info.payments_url, opt_str(out, "payments_url"), "{name}");
        assert_eq!(
            info.terms_of_service,
            opt_str(out, "terms_of_service"),
            "{name}"
        );
    }
}
