#!/usr/bin/env bash
# Run nk's E2E tests against a real nosfry relay (pinned v0.3.0).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
tmpdir="$(mktemp -d)"
server_pid=""

cleanup() {
    if [ -n "$server_pid" ]; then
        kill -- "-$server_pid" 2>/dev/null || kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$tmpdir"
}
trap cleanup EXIT

os="$(uname -s)"; arch="$(uname -m)"
case "$os/$arch" in
    Darwin/arm64) target="aarch64-apple-darwin"; sha="2b82602612c856277a94df829f9b17152d4cab83af6cfd879f3e8adc7c9bbad4" ;;
    Linux/x86_64) target="x86_64-unknown-linux-gnu"; sha="c10776c725ff25f3a6533b32a3027a43b8c3b06f60f03f094906506fc072655a" ;;
    Linux/aarch64) target="aarch64-unknown-linux-gnu"; sha="9f2739294e9f594d2bf474d573f5746c33595aa52f2712dc4c5433a066324c8e" ;;
    *) echo "unsupported platform: $os/$arch" >&2; exit 1 ;;
esac

if [ -n "${NOSFRY_BIN:-}" ]; then
    bin="$NOSFRY_BIN"
else
    dir="$root/target/nosfry-0.3.0/$target"
    bin="$dir/nosfry"
    if [ ! -x "$bin" ]; then
        mkdir -p "$dir"
        tgz="$tmpdir/nosfry.tar.gz"
        curl -fSL --retry 3 -o "$tgz" \
            "https://github.com/qntx/nosfry/releases/download/v0.3.0/nosfry-0.3.0-$target.tar.gz"
        case "$os" in
            Darwin) actual="$(shasum -a 256 "$tgz" | cut -d' ' -f1)" ;;
            *) actual="$(sha256sum "$tgz" | cut -d' ' -f1)" ;;
        esac
        if [ "$actual" != "$sha" ]; then
            echo "sha256 mismatch: got $actual, want $sha" >&2; exit 1
        fi
        tar -xzf "$tgz" -C "$dir"
    fi
fi

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
export NK_E2E_RELAY="ws://127.0.0.1:$port"

cat > "$tmpdir/nosfry.toml" <<CFG
[db]
path = "$tmpdir/db"
[relay]
bind = "127.0.0.1"
port = $port
service_url = "$NK_E2E_RELAY"
CFG

set -m
"$bin" relay --config "$tmpdir/nosfry.toml" > "$tmpdir/relay.log" 2>&1 &
server_pid=$!
set +m

for _ in $(seq 1 600); do
    if curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "nosfry died; log follows" >&2
        cat "$tmpdir/relay.log" >&2
        exit 1
    fi
    sleep 0.05
done
if ! curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
    echo "nosfry never came up; log follows" >&2
    cat "$tmpdir/relay.log" >&2
    exit 1
fi

cargo test -p nk --test e2e --manifest-path "$root/Cargo.toml" -- --ignored "$@"
