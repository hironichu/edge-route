# Deployment

## Scope

EdgeRoute should run on the Linux edge host that owns the OCI VNIC/private IPs and has a NetBird route to the target CIDRs. The default `nft` backend generates nftables rules that DNAT from each edge private IP to a target IP, then SNAT traffic going out `wt0` toward the target CIDRs.

## Requirements

- Linux host, preferably the target OCI shape/architecture.
- `nft` userspace package installed.
- Kernel with nftables enabled: `CONFIG_NF_TABLES=y` or `m`.
- NAT/netfilter modules available for the active kernel. If modules are used, `sudo modprobe nf_tables nf_nat` should succeed.
- IPv4 forwarding enabled: `sudo sysctl -w net.ipv4.ip_forward=1`, then persist in `/etc/sysctl.d/99-edgeroute.conf`.
- Rust toolchain for source builds, or prebuilt `edge` and `edge-agent` binaries.
- OCI direct API auth configured for provisioning, or OCI CLI configured for the current fallback commands.
- NetBird installed and logged in on the edge and on the subnet router side.

The experimental `xdp` backend currently requires no extra runtime dependency because it only builds dry-run plans. It does not attach eBPF programs or change live packet handling.

Run preflight on Linux:

```sh
./scripts/nft-min-check.sh
./scripts/linux-arm64-nft-check.sh
```

`linux-arm64-nft-check.sh` creates a temp SQLite DB, renders a sample ruleset with `edge apply --dry-run`, and checks it with `nft -c`. It does not apply rules.

## NetBird

Create NetBird Network resources for the target LAN CIDRs and assign the home-side Linux peer as their routing peer. Attach a policy that permits the edge peer to reach those resources. On the routing peer, confirm IPv4 forwarding is enabled. Then verify from the edge host:

```sh
netbird status
edge netbird status
edge netbird networks
edge netbird check 10.10.40.89 --ping
```

NetBird manages its own Linux nftables/iptables policy and routing chains. EdgeRoute owns only `table ip edge_nat`; do not flush or rewrite NetBird's tables.

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

Preferred release install:

```sh
curl -fsSL https://raw.githubusercontent.com/hironichu/edge-route/release/X.X.X/scripts/install.sh \
  | sudo env EDGE_VERSION=X.X.X bash
```

The installer detects Linux architecture, the default WAN interface, the NetBird interface, and target CIDRs routed through NetBird. It installs release binaries, `/etc/edge-router/config.toml`, `/etc/edge-router/edge-agent.env`, and the systemd unit. It enables `edge-agent` but does not start it unless `EDGE_START_SERVICE=1` is set.

Common overrides:

```sh
curl -fsSL https://raw.githubusercontent.com/hironichu/edge-route/release/X.X.X/scripts/install.sh \
  | sudo env \
      EDGE_VERSION=X.X.X \
      EDGE_WAN_INTERFACE=enp0s6 \
      EDGE_NETBIRD_INTERFACE=wt0 \
      EDGE_TARGET_CIDRS=10.10.30.0/24,10.10.40.0/24,10.10.50.0/24 \
      EDGE_START_SERVICE=1 \
      bash
```

Manual source install:

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

Adjust `systemd/edge-agent.service` before installing if your WAN interface, target CIDRs, bind address, or database path differ from defaults.

## Create And Validate A Mapping

```sh
edge --config /etc/edge-router/config.toml \
  --db /var/lib/edge-router/state.sqlite \
  --wan-interface enp0s6 \
  --netbird-interface wt0 \
  --target-cidr 10.10.40.0/24 \
  map create \
  --backend nft \
  --edge-private-ip 10.0.0.101 \
  --target 10.10.40.89 \
  --name prod-vm-1

edge --config /etc/edge-router/config.toml --db /var/lib/edge-router/state.sqlite apply --dry-run
sudo edge --config /etc/edge-router/config.toml --db /var/lib/edge-router/state.sqlite apply --check
```

Port-forward mappings allow one reserved public IP and one OCI private IP to front multiple internal services by protocol and public port:

```sh
edge --db /var/lib/edge-router/state.sqlite \
  --target-cidr 10.10.40.0/24 \
  map create \
  --backend nft \
  --mode port_forward_snat \
  --protocol tcp \
  --public-ip <existing_public_ip> \
  --edge-private-ip <internal_private_oracle_ip> \
  --public-port 13306 \
  --target 10.10.40.60 \
  --target-port 3306 \
  --name mysql

edge --db /var/lib/edge-router/state.sqlite \
  --target-cidr 10.10.40.0/24 \
  map create \
  --backend nft \
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
sudo edge --config /etc/edge-router/config.toml --db /var/lib/edge-router/state.sqlite apply
```

## Experimental XDP Planning

Use `backend=xdp` only when you want to inspect the future XDP fast-path plan. XDP mappings must be port-forward mappings and are not applied to live networking yet:

```sh
edge --db /var/lib/edge-router/state.sqlite \
  --target-cidr 10.10.40.0/24 \
  map create \
  --backend xdp \
  --mode port_forward_snat \
  --protocol tcp \
  --public-ip <existing_public_ip> \
  --edge-private-ip <internal_private_oracle_ip> \
  --public-port 13306 \
  --target 10.10.40.60 \
  --target-port 3306 \
  --name mysql-xdp
```

Inspect the XDP plan with dry-run:

```sh
edge --db /var/lib/edge-router/state.sqlite \
  --target-cidr 10.10.40.0/24 \
  reconcile \
  --dry-run \
  --enable-xdp \
  --xdp-interface ens3 \
  --xdp-pin-path /sys/fs/bpf/edgeroute
```

If XDP mappings exist and `--enable-xdp` is omitted, reconcile fails closed instead of silently ignoring them. If XDP mappings exist and dry-run is not set, reconcile fails with `xdp apply is not implemented`.

See [Experimental XDP Backend](xdp.md) for the current plan format and remaining production work.

Optional OCI allocation flow:

```sh
edge oracle ip list --compartment-id <compartment_ocid>
edge oracle ip allocate <mapping_id> --compartment-id <compartment_ocid> --vnic-id <vnic_ocid>
```

Re-run `edge apply --dry-run`, `edge apply --check`, then `edge apply` after allocation changes the mapping's edge/public IP fields.

For reserved public IP reuse, the safe sequence is: list reusable `RESERVED` regional public IPs with no `private-ip-id`, create the new private IP on the forwarding VNIC, assign the existing public IP to that private IP, update SQLite, then dry-run and validate nftables before applying. If the SQLite update fails, unassign the reused public IP rather than deleting it.

See also the [NetBird migration runbook](netbird-migration.md).

Sources: [NetBird routing peers](https://docs.netbird.io/manage/networks/how-routing-peers-work), [NetBird ports and firewalls](https://docs.netbird.io/about-netbird/ports-and-firewalls), [OCI public IPs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm), [OCI private IPs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingIPaddresses.htm), [nftables project](https://www.netfilter.org/projects/nftables/index.html).
