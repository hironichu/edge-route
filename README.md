# EdgeRoute

EdgeRoute is a Linux edge router controller for mapping OCI public/private IPs to home-network targets reachable through Tailscale. It stores mappings in SQLite, renders nftables NAT rules, and can validate rules before applying them.

Core commands:

```sh
cargo build --release -p edge-cli -p edge-agent
./target/release/edge --db /tmp/edge.sqlite --home-cidr 192.168.20.0/24 status
./scripts/nft-min-check.sh
```

Operator docs:

- [Deployment](docs/deployment.md)
- [Recovery](docs/recovery.md)
- [Config example](config/config.example.toml)

Important platform note: nftables verification needs the real Linux kernel netfilter API. macOS and Apple Container can build Rust code, but they cannot prove nft kernel support or parse nftables through Linux netlink. Run `scripts/*nft*.sh` on the target Linux host, a Linux VM, or an OCI Linux instance.
