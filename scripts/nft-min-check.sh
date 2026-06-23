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

[ "$(uname -s)" = "Linux" ] || skip "nft verification requires a Linux kernel"
command -v nft >/dev/null 2>&1 || die "nft command not found"

config_file=""
if [ -r /proc/config.gz ]; then
    config_file="/proc/config.gz"
elif [ -r "/boot/config-$(uname -r)" ]; then
    config_file="/boot/config-$(uname -r)"
fi

if [ -n "$config_file" ]; then
    if [[ "$config_file" = *.gz ]]; then
        zgrep -Eq '^CONFIG_NF_TABLES=(y|m)$' "$config_file" \
            || skip "kernel CONFIG_NF_TABLES is not enabled"
    else
        grep -Eq '^CONFIG_NF_TABLES=(y|m)$' "$config_file" \
            || skip "kernel CONFIG_NF_TABLES is not enabled"
    fi
else
    echo "warn: kernel config not readable; relying on nft parser check" >&2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
rules="$tmpdir/min-edge-router.nft"

cat >"$rules" <<'EOF'
table ip min_edge_router {
    chain input {
        type filter hook input priority 0; policy accept;
    }
}
EOF

nft --version
nft -c -f "$rules"
echo "nft minimal parser check ok"
