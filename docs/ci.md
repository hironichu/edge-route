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

The `Release` workflow runs for tags matching `v*` and can also be started manually with a tag input.

For each release, it builds:

- `edgeroute-<tag>-linux-x86_64.tar.gz`
- `edgeroute-<tag>-linux-arm64.tar.gz`
- matching `.sha256` files

Each archive contains:

- `edge`
- `edge-agent`
- `README.md`
- `docs/`
- `config/`

The publish job creates or updates the GitHub Release for the tag and uploads the artifacts.

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
