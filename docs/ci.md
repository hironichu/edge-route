# CI/CD

## CI Workflow

The `CI` workflow runs on pull requests, pushes to `main`, pushes to `jarvis/**`, and manual dispatch.

Linux architectures:

- `ubuntu-24.04` for x86_64
- `ubuntu-24.04-arm` for arm64

Required gates:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cargo build --workspace --release`
- `scripts/nft-min-check.sh`
- `scripts/linux-arm64-nft-check.sh`
- XDP dry-run fail-closed check
- XDP dry-run plan check
- `cargo doc --workspace --no-deps`

The nft checks install `nftables` and run with `EDGE_NFT_USE_SUDO=1` so GitHub-hosted runners can use `sudo nft -c` when the kernel requires netfilter privileges. The arm64 runner uses native arm64 execution, not emulation.

## Mandatory Safety Coverage

The CI suite covers the behavior that can break live networking:

- mapping validation and conflict rules
- SQLite migrations and DB-level conflict constraints
- concurrent conflicting mapping writes
- nftables render stability
- generated nftables syntax validation
- Linux address parsing
- reconcile dry-run/apply/rollback guardrails
- XDP plan-only behavior and live-apply refusal
- OCI DTO/request construction
- agent API auth and public bind rejection

CI does not apply nftables to the host and does not attach XDP/eBPF programs.

## Release Workflow

The `Release` workflow runs only from branches named `release/X.X.X`, where `X.X.X` is the semantic release version. The workflow validates the branch name and uses `X.X.X` as the GitHub Release name, release tag, and artifact version.

For each release, it builds:

- `edgeroute-X.X.X-linux-x86_64.tar.gz`
- `edgeroute-X.X.X-linux-arm64.tar.gz`
- matching `.sha256` files

Each archive contains:

- `edge`
- `edge-agent`
- `README.md`
- `docs/`
- `config/`
- `scripts/`
- `systemd/`

The publish job creates or updates the GitHub Release for `X.X.X` and uploads the artifacts. Release branches that do not match `release/[0-9]+.[0-9]+.[0-9]+` fail before build or publish.

## Release Installer

The release archive includes `scripts/install.sh`. Operators can run the installer directly from the matching release branch:

```sh
curl -fsSL https://raw.githubusercontent.com/hironichu/edge-route/release/X.X.X/scripts/install.sh \
  | sudo env EDGE_VERSION=X.X.X bash
```

The installer downloads the matching GitHub Release artifact, verifies its `.sha256`, installs `edge` and `edge-agent`, writes standard directories, installs the systemd unit, and creates `/etc/edge-router/edge-agent.env` when missing.

Detection and safety behavior:

- Linux only; x86_64 and arm64 are supported.
- Requires systemd for the standard service setup.
- Detects the default WAN interface from the default IPv4 route.
- Detects `tailscale0` or another `tailscale*` interface.
- Detects home CIDRs from routes through the Tailscale interface, with `192.168.0.0/16` as a fallback.
- Runs `nft -c` against a minimal ruleset but does not apply firewall rules.
- Enables `edge-agent` but does not start it unless `EDGE_START_SERVICE=1` is set.

Override detection with `EDGE_WAN_INTERFACE`, `EDGE_TAILSCALE_INTERFACE`, `EDGE_HOME_CIDRS`, `EDGE_REPO`, `EDGE_INSTALL_PACKAGES=0`, or `EDGE_OVERWRITE_CONFIG=1`.

## Local Parity

Before opening or updating a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --workspace --release
```

On Linux with nftables:

```sh
./scripts/nft-min-check.sh
EDGE_ALLOW_NON_ARM64=1 ./scripts/linux-arm64-nft-check.sh
```

If your local user needs elevated nft privileges:

```sh
EDGE_NFT_USE_SUDO=1 ./scripts/nft-min-check.sh
EDGE_ALLOW_NON_ARM64=1 EDGE_NFT_USE_SUDO=1 ./scripts/linux-arm64-nft-check.sh
```
