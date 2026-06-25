# Web GUI

EdgeRoute GUI is served by `edge-gateway`. It is not mixed into `edge-agent`: privileged nft/Linux/Tailscale work remains in `edge-agent`, while `edge-gateway` renders management screens and talks to `edge-agent` over the Unix socket.

## Runtime Shape

```txt
tailnet browser -> edge-gateway HTTP :8080 -> /run/edge-router/edge-agent.sock -> edge-agent
```

Transport security and access control are expected from Tailscale. Bind `edge-gateway` to loopback for local use, or to the node's Tailscale IP for remote operators. Do not bind to `0.0.0.0`; the binary refuses wildcard binds.

The UI uses:

- Rust server-rendered HTML fragments with `maud`.
- HTMX for swaps and forms.
- Tiny vanilla JS only for Ctrl/Cmd+K command palette and transitions.
- Static CSS, no Node.js, no Vite, no React, no browser-side data model.

Every UI value is rendered from the real `edge-agent` API:

- `GET /v1/status`
- `GET|POST /v1/mappings`
- `POST /v1/mappings/{id}/enable`
- `POST /v1/mappings/{id}/disable`
- `DELETE /v1/mappings/{id}`
- `POST /v1/apply/dry-run`
- `POST /v1/reconcile`
- `GET /v1/tailscale/status`
- `GET /v1/tailscale/routes`
- `GET /v1/events`

## Tailscale Grant

Example grant shape restricting access to tagged edge gateway nodes:

```json
{
  "src": ["group:ops"],
  "dst": ["tag:edge-gateway"],
  "ip": ["tcp:8080"]
}
```

Set `EDGE_GATEWAY_BIND` to the Tailscale IP and port allowed by your ACL/grant.

## Install UI Assets

No build step. Install only the shipped static assets:

```sh
sudo install -d -m 0755 /usr/share/edgeroute-ui
sudo install -m 0644 \
  web/edgeroute-ui/index.html \
  web/edgeroute-ui/app.css \
  web/edgeroute-ui/app.js \
  web/edgeroute-ui/htmx.min.js \
  /usr/share/edgeroute-ui/
```

## Gateway Config

Environment-file example:

```sh
sudo install -d -m 0750 /etc/edge-router
sudo sh -c 'umask 077; cat > /etc/edge-router/edge-gateway.env' <<'EOF'
EDGE_GATEWAY_BIND=127.0.0.1:8080
EDGE_AGENT_SOCKET=/run/edge-router/edge-agent.sock
EDGE_GATEWAY_STATIC_DIR=/usr/share/edgeroute-ui
EDGE_API_TOKEN=replace-with-edge-agent-api-token
EOF
```

`EDGE_GATEWAY_TOKEN` is optional. If set, it gates raw `/api/*` JSON proxy requests. The server-rendered `/ui/*` pages rely on Tailscale grants instead.

## System Users

The systemd units expect an `edge-router` group shared by `edge-agent` and `edge-gateway`, so the unprivileged gateway can connect to `/run/edge-router/edge-agent.sock`:

```sh
sudo groupadd --system edge-router || true
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid edge-router edge-gateway || true
```

## Local Development

Run against a real agent:

```sh
cargo run -p edge-gateway -- \
  --api-token dev-agent-token \
  --static-dir web/edgeroute-ui
```

Run without an agent using compile-time sample data:

```sh
cargo run -p edge-gateway --features mock -- --static-dir web/edgeroute-ui
```

The `mock` feature is off by default. Release builds do not include sample UI data.
