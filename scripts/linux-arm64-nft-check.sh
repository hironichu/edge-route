#!/usr/bin/env bash
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

skip() {
    echo "skip: $*" >&2
    exit 78
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

[ "$(uname -s)" = "Linux" ] || skip "nft verification requires Linux, not macOS or Apple Container"
case "$(uname -m)" in
    aarch64 | arm64) ;;
    *)
        [ "${EDGE_ALLOW_NON_ARM64:-0}" = "1" ] \
            || skip "expected Linux arm64/aarch64; set EDGE_ALLOW_NON_ARM64=1 to run anyway"
        ;;
esac

command -v nft >/dev/null 2>&1 || die "nft command not found"
"$script_dir/nft-min-check.sh"

nft_cmd=(nft)
if [ "${EDGE_NFT_USE_SUDO:-0}" = "1" ]; then
    command -v sudo >/dev/null 2>&1 || die "sudo command not found"
    nft_cmd=(sudo nft)
fi

if [ "${1:-}" = "parse-only" ]; then
    rules="${2:-${EDGE_NFT_FILE:-/tmp/edge-router-generated.nft}}"
    [ -r "$rules" ] || die "rules file not readable: $rules"
    "${nft_cmd[@]}" --version
    "${nft_cmd[@]}" -c -f "$rules"
    echo "nft generated rules check ok: $rules"
    exit 0
fi

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
tmpdb="$tmpdir/edge-router.sqlite"
generated="$tmpdir/edge-router-generated.nft"

cargo run -q --manifest-path "$repo_root/Cargo.toml" -p edge-cli -- \
    --db "$tmpdb" \
    --home-cidr "${EDGE_HOME_CIDR:-192.168.20.0/24}" \
    map create \
    --edge-private-ip "${EDGE_EDGE_PRIVATE_IP:-10.0.0.101}" \
    --target "${EDGE_TARGET_IP:-192.168.20.42}" \
    --name "${EDGE_MAP_NAME:-prod-vm-1}" \
    --skip-route-check >"$tmpdir/create.out"
cargo run -q --manifest-path "$repo_root/Cargo.toml" -p edge-cli -- \
    --db "$tmpdb" \
    --home-cidr "${EDGE_HOME_CIDR:-192.168.20.0/24}" \
    apply --dry-run >"$generated"

"${nft_cmd[@]}" --version
"${nft_cmd[@]}" -c -f "$generated"
echo "nft generated rules check ok"
