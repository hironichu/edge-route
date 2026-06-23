#!/usr/bin/env bash
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

warn() {
    echo "warn: $*" >&2
}

info() {
    echo "info: $*" >&2
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "$1 command not found"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "x86_64" ;;
        aarch64 | arm64) echo "arm64" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    else
        echo ""
    fi
}

install_packages() {
    [ "${EDGE_INSTALL_PACKAGES:-1}" = "1" ] || return 0

    case "$(detect_pkg_manager)" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --no-install-recommends ca-certificates curl tar openssl iproute2 nftables
            ;;
        dnf)
            dnf install -y ca-certificates curl tar openssl iproute nftables
            ;;
        yum)
            yum install -y ca-certificates curl tar openssl iproute nftables
            ;;
        *)
            warn "no supported package manager found; assuming required packages are already installed"
            ;;
    esac
}

latest_release_version() {
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1
}

detect_wan_interface() {
    if [ -n "${EDGE_WAN_INTERFACE:-}" ]; then
        echo "$EDGE_WAN_INTERFACE"
        return
    fi

    ip -o -4 route show default 2>/dev/null \
        | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

detect_tailscale_interface() {
    if [ -n "${EDGE_TAILSCALE_INTERFACE:-}" ]; then
        echo "$EDGE_TAILSCALE_INTERFACE"
        return
    fi

    if ip link show tailscale0 >/dev/null 2>&1; then
        echo "tailscale0"
        return
    fi

    ip -o link show 2>/dev/null \
        | awk -F': ' '$2 ~ /^tailscale[0-9]*/ { print $2; exit }'
}

detect_home_cidrs() {
    local tailscale_interface="$1"

    if [ -n "${EDGE_HOME_CIDRS:-}" ]; then
        echo "$EDGE_HOME_CIDRS"
        return
    fi

    if [ -n "$tailscale_interface" ]; then
        { ip -4 route show table all dev "$tailscale_interface" 2>/dev/null || true; } \
            | awk '
                $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ &&
                $1 != "100.64.0.0/10" &&
                $1 != "169.254.0.0/16" {
                    if (!seen[$1]++) {
                        if (out != "") out = out ","
                        out = out $1
                    }
                }
                END { print out }
            '
        return
    fi

    echo ""
}

toml_array() {
    local csv="$1"
    local output=""
    local item
    IFS=',' read -r -a items <<<"$csv"
    for item in "${items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [ -n "$item" ] || continue
        if [ -n "$output" ]; then
            output="${output}, "
        fi
        output="${output}\"${item}\""
    done
    printf '[%s]\n' "$output"
}

write_config_if_missing() {
    local config_file="$1"
    local wan_interface="$2"
    local tailscale_interface="$3"
    local home_cidrs="$4"

    if [ -f "$config_file" ] && [ "${EDGE_OVERWRITE_CONFIG:-0}" != "1" ]; then
        info "keeping existing $config_file"
        return
    fi

    install -d -m 0750 "$(dirname "$config_file")"
    umask 027
    {
        printf 'wan_interface = "%s"\n' "$wan_interface"
        printf 'tailscale_interface = "%s"\n' "$tailscale_interface"
        printf 'home_cidrs = %s\n' "$(toml_array "$home_cidrs")"
        printf '\n'
        printf '# Optional OCI defaults used by CLI/API provisioning.\n'
        printf '# oci_compartment_id = "ocid1.compartment..."\n'
        printf '# oci_vnic_id = "ocid1.vnic..."\n'
        printf '# oci_subnet_id = "ocid1.subnet..."\n'
        printf '# oci_region = "eu-paris-1"\n'
        printf '# oci_auth = "instance_principal"\n'
        printf '# oci_nsg_ids = ["ocid1.networksecuritygroup..."]\n'
    } >"$config_file"
    chmod 0640 "$config_file"
}

write_env_if_missing() {
    local env_file="$1"

    if [ -f "$env_file" ]; then
        info "keeping existing $env_file"
        return
    fi

    install -d -m 0750 "$(dirname "$env_file")"
    umask 077
    printf 'EDGE_API_TOKEN=%s\n' "$(openssl rand -hex 32)" >"$env_file"
    chmod 0600 "$env_file"
}

verify_nft_parser() {
    local tmpdir
    local rules
    tmpdir="$(mktemp -d)"
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
    rm -rf "$tmpdir"
}

main() {
    [ "$(uname -s)" = "Linux" ] || die "EdgeRoute installer requires Linux"
    [ "${EUID:-$(id -u)}" -eq 0 ] || die "run as root, for example: curl -fsSL <url> | sudo env EDGE_VERSION=X.X.X bash"

    local repo="${EDGE_REPO:-hironichu/edge-route}"
    local version="${EDGE_VERSION:-${1:-}}"
    local arch
    local asset
    local base_url
    local tmpdir
    local package_dir
    local wan_interface
    local tailscale_interface
    local home_cidrs

    install_packages

    need_cmd curl
    need_cmd tar
    need_cmd install
    need_cmd ip
    need_cmd nft
    need_cmd openssl
    need_cmd systemctl
    need_cmd sha256sum

    [ -d /run/systemd/system ] || die "systemd is required for the standard service setup"

    arch="$(detect_arch)"
    if [ -z "$version" ]; then
        version="$(latest_release_version "$repo")"
    fi
    [ -n "$version" ] || die "release version not provided and latest release could not be detected"

    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "release version must look like X.X.X, got: $version"

    wan_interface="$(detect_wan_interface)"
    [ -n "$wan_interface" ] || die "could not detect WAN interface; set EDGE_WAN_INTERFACE"

    tailscale_interface="$(detect_tailscale_interface)"
    [ -n "$tailscale_interface" ] || die "could not detect Tailscale interface; set EDGE_TAILSCALE_INTERFACE"

    home_cidrs="$(detect_home_cidrs "$tailscale_interface")"
    if [ -z "$home_cidrs" ]; then
        home_cidrs="192.168.0.0/16"
        warn "could not detect home CIDRs through $tailscale_interface; using $home_cidrs. Override with EDGE_HOME_CIDRS."
    fi

    verify_nft_parser

    asset="edgeroute-${version}-linux-${arch}.tar.gz"
    base_url="https://github.com/${repo}/releases/download/${version}"
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    info "downloading ${asset} from ${repo}"
    curl -fL -o "$tmpdir/$asset" "$base_url/$asset"
    curl -fL -o "$tmpdir/$asset.sha256" "$base_url/$asset.sha256"
    (cd "$tmpdir" && sha256sum -c "$asset.sha256")

    tar -C "$tmpdir" -xzf "$tmpdir/$asset"
    package_dir="$tmpdir/edgeroute-${version}-linux-${arch}"
    [ -x "$package_dir/edge" ] || die "edge binary missing from release asset"
    [ -x "$package_dir/edge-agent" ] || die "edge-agent binary missing from release asset"
    [ -f "$package_dir/systemd/edge-agent.service" ] || die "systemd unit missing from release asset"

    install -m 0755 "$package_dir/edge" /usr/local/bin/edge
    install -m 0755 "$package_dir/edge-agent" /usr/local/bin/edge-agent
    install -d -m 0750 /var/lib/edge-router /run/edge-router /etc/edge-router
    write_config_if_missing /etc/edge-router/config.toml "$wan_interface" "$tailscale_interface" "$home_cidrs"
    write_env_if_missing /etc/edge-router/edge-agent.env
    install -m 0644 "$package_dir/systemd/edge-agent.service" /etc/systemd/system/edge-agent.service

    systemctl daemon-reload
    systemctl enable edge-agent

    if [ "${EDGE_START_SERVICE:-0}" = "1" ]; then
        systemctl restart edge-agent
        systemctl --no-pager --full status edge-agent || true
    else
        info "service enabled but not started; set EDGE_START_SERVICE=1 to start during install"
    fi

    info "installed EdgeRoute ${version}"
    info "detected wan_interface=${wan_interface}"
    info "detected tailscale_interface=${tailscale_interface}"
    info "configured home_cidrs=${home_cidrs}"
}

main "$@"
