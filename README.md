# EdgeRoute

EdgeRoute is a Linux edge router controller for mapping OCI public/private IPs to home-network targets reachable through Tailscale. It stores mappings in SQLite, renders nftables NAT rules, and can validate rules before applying them. The default and only live data plane today is `nft`; an experimental `xdp` backend can build dry-run forwarding plans but intentionally refuses live apply until an eBPF loader/attach path exists.

Core commands:

```sh
cargo build --release -p edge-cli -p edge-agent
./target/release/edge --db /tmp/edge.sqlite --home-cidr 192.168.20.0/24 status
./scripts/nft-min-check.sh
```

CI/CD:

- Pull requests and pushes run Rust formatting, clippy, tests, release builds, nft parser checks, and XDP dry-run safety checks on Linux x86_64 and arm64.
- Tags matching `v*` build Linux x86_64 and arm64 release tarballs for `edge` and `edge-agent`.

Operator docs:

- [Deployment](docs/deployment.md)
- [CI/CD](docs/ci.md)
- [Experimental XDP backend](docs/xdp.md)
- [Recovery](docs/recovery.md)
- [Config example](config/config.example.toml)

Important platform note: nftables verification needs the real Linux kernel netfilter API. macOS and Apple Container can build Rust code, but they cannot prove nft kernel support or parse nftables through Linux netlink. Run `scripts/*nft*.sh` on the target Linux host, a Linux VM, or an OCI Linux instance.
