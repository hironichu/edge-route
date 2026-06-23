#!/usr/bin/env bash
set -euo pipefail

skip() {
    echo "skip: $*" >&2
    exit 78
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

[ "$(uname -s)" = "Linux" ] || skip "Linux arm64 verification requires Linux"
case "$(uname -m)" in
    aarch64 | arm64) ;;
    *)
        [ "${EDGE_ALLOW_NON_ARM64:-0}" = "1" ] \
            || skip "expected Linux arm64/aarch64; set EDGE_ALLOW_NON_ARM64=1 to run anyway"
        ;;
esac

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

rustc --version
cargo --version
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/edge-target}" \
    cargo test --manifest-path "$repo_root/Cargo.toml" --workspace

set +e
"$script_dir/linux-arm64-nft-check.sh"
nft_status=$?
set -e
if [ "$nft_status" -eq 78 ]; then
    echo "skip: nft parser verification unavailable on this kernel" >&2
elif [ "$nft_status" -ne 0 ]; then
    exit "$nft_status"
fi
