# Deployment

## Scope

EdgeRoute should run on the Linux edge host that owns the OCI VNIC/private IPs and has a Tailscale route to the home CIDRs. The generated nftables rules do DNAT from each edge private IP to a target IP, then SNAT traffic going out `tailscale0` toward the home CIDRs.

## Requirements

- Linux host, preferably the target OCI shape/architecture.
- `nft` userspace package installed.
- Kernel with nftables enabled: `CONFIG_NF_TABLES=y` or `m`.
- NAT/netfilter modules available for the active kernel. If modules are used, `sudo modprobe nf_tables nf_nat` should succeed.
- IPv4 forwarding enabled: `sudo sysctl -w net.ipv4.ip_forward=1`, then persist in `/etc/sysctl.d/99-edgeroute.conf`.
- Rust toolchain for source builds, or prebuilt `edge` and `edge-agent` binaries.
- OCI direct API auth configured for provisioning, or OCI CLI configured for the current fallback commands.
- Tailscale installed and logged in on the edge and on the subnet router side.

Run preflight on Linux:

```sh
./scripts/nft-min-check.sh
./scripts/linux-arm64-nft-check.sh
```

`linux-arm64-nft-check.sh` creates a temp SQLite DB, renders a sample ruleset with `edge apply --dry-run`, and checks it with `nft -c`. It does not apply rules.

## Tailscale

On the home-side subnet router, advertise the target LAN:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo tailscale up --advertise-routes=192.168.20.0/24
```

Approve the advertised route in the Tailscale admin console. On the edge host, accept routes if required by your setup, then verify:

```sh
tailscale status
edge tailscale status
edge tailscale routes
edge tailscale check 192.168.20.42 --ping
```

Tailscale can manage Linux firewall rules through iptables or nftables. Do not set Tailscale netfilter mode to `off` unless you intentionally own all required Tailscale firewall rules.

## OCI Policy Notes

EdgeRoute models OCI changes as explicit provisioning operations: create or reuse a reserved public IP, assign it to an OCI private IP on the forwarding VNIC, and optionally add narrow ingress rules to configured NSGs. Start in a non-production compartment.

Minimum policy shape to validate with your tenancy:

```text
Allow group EdgeRouteOperators to use vnics in compartment <compartment>
Allow group EdgeRouteOperators to manage private-ips in compartment <compartment>
Allow group EdgeRouteOperators to manage public-ips in compartment <compartment>
Allow group EdgeRouteOperators to manage network-security-groups in compartment <compartment>
```

If your tenancy policy model does not accept the granular resource types, use a broader temporary policy such as `manage virtual-network-family` in the test compartment, then reduce it after confirming the exact API calls. Prefer NSGs for EdgeRoute-managed security rules; subnet security lists are deliberately left operator-managed unless you add that scope explicitly. The public subnet, route table, internet gateway, and NSG ingress still control whether the assigned public IP is reachable.

## Install

```sh
cargo build --release -p edge-cli -p edge-agent
sudo install -m 0755 target/release/edge /usr/local/bin/edge
sudo install -m 0755 target/release/edge-agent /usr/local/bin/edge-agent
sudo install -d -m 0750 /var/lib/edge-router /run/edge-router
sudo install -d -m 0750 /etc/edge-router
sudo install -m 0640 config/config.example.toml /etc/edge-router/config.toml
sudo sh -c 'umask 077; printf "EDGE_API_TOKEN=%s\n" "$(openssl rand -hex 32)" > /etc/edge-router/edge-agent.env'
sudo install -m 0644 systemd/edge-agent.service /etc/systemd/system/edge-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now edge-agent
```

Adjust `systemd/edge-agent.service` before installing if your WAN interface, home CIDRs, bind address, or database path differ from defaults.

## Create And Validate A Mapping

```sh
edge --db /var/lib/edge-router/state.sqlite \
  --wan-interface ens3 \
  --tailscale-interface tailscale0 \
  --home-cidr 192.168.20.0/24 \
  map create \
  --edge-private-ip 10.0.0.101 \
  --target 192.168.20.42 \
  --name prod-vm-1

edge --db /var/lib/edge-router/state.sqlite --home-cidr 192.168.20.0/24 apply --dry-run
sudo edge --db /var/lib/edge-router/state.sqlite --home-cidr 192.168.20.0/24 apply --check
```

Port-forward mappings allow one reserved public IP and one OCI private IP to front multiple internal services by protocol and public port:

```sh
edge --db /var/lib/edge-router/state.sqlite \
  --home-cidr 10.10.40.0/24 \
  map create \
  --mode port_forward_snat \
  --protocol tcp \
  --public-ip <existing_public_ip> \
  --edge-private-ip <internal_private_oracle_ip> \
  --public-port 13306 \
  --target 10.10.40.60 \
  --target-port 3306 \
  --name mysql

edge --db /var/lib/edge-router/state.sqlite \
  --home-cidr 10.10.40.0/24 \
  map create \
  --mode port_forward_snat \
  --protocol udp \
  --public-ip <existing_public_ip> \
  --edge-private-ip <internal_private_oracle_ip> \
  --public-port 14444 \
  --target 10.10.40.60 \
  --target-port 4444 \
  --name udp-service
```

Only apply after dry-run and check look correct:

```sh
sudo edge --db /var/lib/edge-router/state.sqlite --home-cidr 192.168.20.0/24 apply
```

Optional OCI allocation flow:

```sh
edge oracle ip list --compartment-id <compartment_ocid>
edge oracle ip allocate <mapping_id> --compartment-id <compartment_ocid> --vnic-id <vnic_ocid>
```

Re-run `edge apply --dry-run`, `edge apply --check`, then `edge apply` after allocation changes the mapping's edge/public IP fields.

For reserved public IP reuse, the safe sequence is: list reusable `RESERVED` regional public IPs with no `private-ip-id`, create the new private IP on the forwarding VNIC, assign the existing public IP to that private IP, update SQLite, then dry-run and validate nftables before applying. If the SQLite update fails, unassign the reused public IP rather than deleting it.

Sources: [Tailscale subnet routers](https://tailscale.com/docs/features/subnet-routers), [Tailscale firewall mode](https://tailscale.com/docs/features/firewall-mode), [OCI public IPs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm), [OCI private IPs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingIPaddresses.htm), [nftables project](https://www.netfilter.org/projects/nftables/index.html).
