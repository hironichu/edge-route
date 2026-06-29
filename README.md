# EdgeRoute

EdgeRoute is a Linux edge router controller for mapping OCI public/private IPs to home-network targets reachable through Tailscale. It stores mappings in SQLite, renders nftables NAT rules, and can validate rules before applying them. The default and only live data plane today is `nft`; an experimental `xdp` backend can build dry-run forwarding plans but intentionally refuses live apply until an eBPF loader/attach path exists.

Two ways to drive it:

- `edge-cli` — the `edge` command-line tool for mappings, reconcile, and Oracle (OCI) IP/VNIC operations.
- `edge-gateway` — a web UI for the same operations. Server-rendered HTML (`maud` + HTMX, no Node/React), it renders every value from the live `edge-agent` API and never touches nft/Linux/Tailscale directly. Pages: Dashboard, Mappings (create/enable/disable/delete), Tools (ping, port-test, tcpdump, ruleset dry-run, reconcile-check), Topology, Oracle, Reconcile (run + dry-run), Tailscale, Logs (live events + download). Auth and transport come from Tailscale; the binary refuses wildcard (`0.0.0.0`) binds.

Core commands:

```sh
cargo build --release -p edge-cli -p edge-agent -p edge-gateway
./target/release/edge --db /tmp/edge.sqlite --home-cidr 192.168.20.0/24 status
./scripts/nft-min-check.sh

# Web UI: bind to loopback (local) or the node's Tailscale IP (remote operators)
EDGE_API_TOKEN=... ./target/release/edge-gateway --bind 127.0.0.1:8080
```

CI/CD:

- Pull requests and pushes run Rust formatting, clippy, tests, release builds, nft parser checks, and XDP dry-run safety checks on Linux x86_64 and arm64.
- Branches named `release/X.X.X` publish Linux x86_64 and arm64 release tarballs for `edge` and `edge-agent` using `X.X.X` as the release name.

Install from a release branch:

```sh
curl -fsSL https://raw.githubusercontent.com/hironichu/edge-route/release/X.X.X/scripts/install.sh \
  | sudo env EDGE_VERSION=X.X.X bash
```

Operator docs:

- [Deployment](docs/deployment.md)
- [Web GUI](docs/gui.md)
- [CI/CD](docs/ci.md)
- [Experimental XDP backend](docs/xdp.md)
- [Recovery](docs/recovery.md)
- [Config example](config/config.example.toml)

Important platform note: nftables verification needs the real Linux kernel netfilter API. macOS and Apple Container can build Rust code, but they cannot prove nft kernel support or parse nftables through Linux netlink. Run `scripts/*nft*.sh` on the target Linux host, a Linux VM, or an OCI Linux instance.
