# Experimental XDP Backend

## Status

The `xdp` backend is an experimental planning plugin. It does not attach an eBPF program, update pinned BPF maps, or change live traffic yet.

Current behavior:

- `backend=nft` remains the default production data plane.
- `backend=xdp` is accepted only for `port_forward_snat` mappings.
- XDP dry-runs build a deterministic forwarding plan.
- XDP live apply fails closed with `xdp apply is not implemented`.
- `backend=proxy` is still rejected until an L7 proxy plugin exists.

## Supported Mapping Shape

XDP planning supports only simple L4 port forwards:

```txt
edge_private_ip + protocol + public_port -> target_ip + target_port
```

Supported:

- `mode=port_forward_snat`
- `protocol=tcp`
- `protocol=udp`
- explicit `public_port`
- explicit `target_port`
- target IP inside configured `target_cidrs`

Not supported:

- `mode=one_to_one_snat`
- `protocol=all`
- L7 routing
- TLS/SNI/HTTP inspection
- live attach/apply

## Create An XDP Mapping

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

## Inspect The Plan

Dry-run with XDP explicitly enabled:

```sh
edge --db /var/lib/edge-router/state.sqlite \
  --target-cidr 10.10.40.0/24 \
  reconcile \
  --dry-run \
  --enable-xdp \
  --xdp-interface ens3 \
  --xdp-pin-path /sys/fs/bpf/edgeroute
```

The command prints the nftables config and reports the number of XDP plan entries. It does not attach XDP or change BPF maps.

HTTP API equivalent:

```json
{
  "dry_run": true,
  "include_config": true,
  "enable_xdp": true,
  "xdp_interface": "ens3",
  "xdp_pin_path": "/sys/fs/bpf/edgeroute"
}
```

POST that body to `/v1/reconcile`. The response includes `xdp_plan_entries`.

## Safety Behavior

If XDP mappings exist and XDP planning is not enabled, reconcile fails instead of silently ignoring those mappings.

If XDP mappings exist and dry-run is not set, reconcile fails before nft/Linux apply:

```txt
xdp apply is not implemented; run dry-run to inspect the XDP plan
```

This preserves the current production behavior: only nft-backed mappings are applied to live networking.

## Internal Plan Format

The XDP plugin builds entries shaped like:

```txt
key:
  edge_private_ip
  protocol
  public_port

value:
  target_ip
  target_port
  flags
```

The key and value expose stable byte serialization in network byte order so a later loader can update pinned BPF maps without changing the EdgeRoute control-plane model.

## Future Apply Path

A production XDP backend still needs:

- compiled eBPF program artifact
- loader with `skb` mode first, native mode later
- pinned map creation and atomic update flow
- generation snapshots for rollback
- interface attach/detach validation
- health and packet counter reporting
- fallback policy back to nft or disabled mapping state
