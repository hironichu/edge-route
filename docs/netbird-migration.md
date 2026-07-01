# NetBird Migration Runbook

This runbook migrates an existing EdgeRoute gateway to the NetBird-only contract. It does not change NetBird policies or live firewall state automatically.

## 1. Back Up And Inventory

Run on the edge host before installing the new release:

```sh
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 "/root/edgeroute-backup-$stamp"
sudo cp -a /etc/edge-router "/root/edgeroute-backup-$stamp/"
sudo cp -a /var/lib/edge-router/state.sqlite* "/root/edgeroute-backup-$stamp/"
sudo cp -a /etc/systemd/system/edge-agent.service /etc/systemd/system/edge-gateway.service "/root/edgeroute-backup-$stamp/" 2>/dev/null || true
sudo nft -a list ruleset >"/root/edgeroute-backup-$stamp/nftables.txt"
sudo iptables-save >"/root/edgeroute-backup-$stamp/iptables.txt"
sudo /usr/local/bin/edge status >"/root/edgeroute-backup-$stamp/edge-status.txt" 2>&1 || true
```

Confirm NetBird and the routed targets before touching EdgeRoute:

```sh
netbird status
ip route get 10.10.40.88
ip route get 10.10.40.89
ping -c 3 -W 2 10.10.40.88
ping -c 3 -W 2 10.10.40.89
```

Both routes must report `dev wt0`; policy-table output such as `table netbird` is valid.

## 2. Install Without Applying

Use this initial `/etc/edge-router/config.toml`:

```toml
wan_interface = "enp0s6"
netbird_interface = "wt0"
target_cidrs = ["10.10.30.0/24", "10.10.40.0/24", "10.10.50.0/24"]
```

Preserve the existing OCI and API-token settings below those fields. Install the release with `EDGE_START_SERVICE=0`. A supplied config file is authoritative in the NetBird release and replaces stale configuration stored in SQLite.

Validate without applying:

```sh
sudo /usr/local/bin/edge \
  --config /etc/edge-router/config.toml \
  --db /var/lib/edge-router/state.sqlite \
  status

sudo /usr/local/bin/edge netbird status
sudo /usr/local/bin/edge netbird networks
sudo /usr/local/bin/edge netbird check 10.10.40.88 --ping
sudo /usr/local/bin/edge netbird check 10.10.40.89 --ping

sudo /usr/local/bin/edge \
  --config /etc/edge-router/config.toml \
  --db /var/lib/edge-router/state.sqlite \
  apply --dry-run --check \
  | sudo tee /run/edge-router/netbird-dry-run.nft
```

The dry run must contain both mappings and `oifname "wt0"` masquerade rules for all three target CIDRs. It must not contain `tailscale0`.

## 3. Reconcile Routed Targets

```sh
sudo systemctl daemon-reload
sudo systemctl restart edge-agent
sudo systemctl --no-pager --full status edge-agent
sudo /usr/local/bin/edge --db /var/lib/edge-router/state.sqlite status
sudo /usr/local/bin/edge --db /var/lib/edge-router/state.sqlite reconcile
sudo nft list table ip edge_nat
```

Verify the public OCI endpoint mapped to `10.0.0.101 → 10.10.40.88` and the endpoint mapped to `10.0.0.102 → 10.10.40.89` from an external client. Do not proceed if either path fails.

## 4. Expose The Gateway

In NetBird, create an `edgeroute-operators` group and a unidirectional peer policy allowing that group to reach `mainvnic` on TCP/8080. Remove or narrow any broader policy that would also permit TCP/8080. Keep SSH policy separate.

After confirming the policy is distributed, set:

```text
EDGE_GATEWAY_BIND=100.64.65.67:8080
```

Restart `edge-gateway`, then verify access from one authorized peer and rejection from one unauthorized peer.

## 5. Remove Stale Rules

Only after routed forwarding works, inspect the saved and live iptables rules:

```sh
sudo iptables-save | grep -n 'tailscale0' || true
```

Delete only the exact legacy rules referencing `tailscale0`, using matching `iptables -D` commands. Never flush the shared `filter` tables, and never alter the `ip netbird`, `ip6 netbird`, or `ip edge_nat` tables as part of this cleanup.

## 6. Enable Direct NetBird Targets Separately

In a later change window, append the overlay range:

```toml
target_cidrs = [
  "10.10.30.0/24",
  "10.10.40.0/24",
  "10.10.50.0/24",
  "100.64.0.0/16",
]
```

Create a NetBird policy from `mainvnic` to the specific target and service, restart the agent so the authoritative file is persisted, and verify `edge netbird check <target> --ping`. Run another dry-run and reconcile before creating the direct-peer mapping. `Idle` is a healthy NetBird lazy-connection state and should become connected when traffic begins.

