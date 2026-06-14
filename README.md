# tbox

[![test](https://github.com/juliuswwj/tbox/actions/workflows/test.yml/badge.svg)](https://github.com/juliuswwj/tbox/actions/workflows/test.yml)

A VLESS-REALITY tunnel built on [sing-box](https://sing-box.sagernet.org/),
serving two purposes over one censorship-resistant link that looks like ordinary
HTTPS traffic to a real site (e.g. `www.microsoft.com`):

1. **Service publishing** — expose local services through the VPS, identified by
   a URL whose scheme picks the mode:
   - `https://host/path` — an **HTTP** service as a full site or sub-location,
     with nginx-style URL/header rewriting;
   - `wss://host/path` — a raw **TCP** service as a **WebSocket**;
   - `tcp://host` — a raw **TCP** service as **TLS+TCP** (TLS terminated by SNI,
     then piped raw — e.g. ssh).

   These coexist under one certificate, e.g. all of `https://dc.example.com/`,
   `https://app.dc.example.com/location/`, `wss://app.dc.example.com/tunnel/ssh`,
   and `tcp://ssh.dc.example.com` served by a cert for `[dc.example.com,
   *.dc.example.com]`.
2. **SOCKS5H proxy** — a local SOCKS5H port whose traffic egresses from the VPS,
   to get through a monitored gateway.

```
 local apps ──socks5h──▶ tbox client ══VLESS-REALITY══▶ tbox server (VPS) ──▶ internet
                              ║         (looks like HTTPS         ║  :443 SNI router
 local services ◀══reverse════╝          to the mimic host)       ║
                                                                   ▼
 public client ──https://app.example.com──────────────────────────┘
        (TLS terminated on the VPS, reverse-proxied to the client over the tunnel)
```

## How it works

- The **server** owns `:443` with an L4 SNI router. By SNI host:
  - a **tcp service** → TLS terminated on the VPS, then raw-piped to the owning
    client (TLS+TCP);
  - a host with **http/ws services** → handed to the publish HTTP server, which
    terminates TLS (cert chosen by SNI) and dispatches by path;
  - the **mimic** host (and unknown/empty SNI, probes) → embedded sing-box
    VLESS-REALITY inbound, which serves authenticated proxy clients and falls
    back to the genuine mimic site for everyone else.
- **Certs are decoupled from services.** A certificate is matched to a host by
  its SAN (wildcards supported), so you never repeat the domain in config. Certs
  may be provided by the **server** (in `server.yaml`, avoiding client-side cert
  dependencies) or uploaded by a **client**. A service only needs *some* cert
  whose SAN covers its host.
- The **client** runs an embedded sing-box (SOCKS5H inbound + VLESS-REALITY
  outbound). Forward proxying is pure sing-box. For publishing it opens one
  carrier connection through the tunnel and runs a
  [yamux](https://github.com/hashicorp/yamux) session over it, so the server can
  open reverse streams toward the client per request.
- **Multi-client & shared hosts**: the server lists several client credentials
  (one VLESS UUID each). http/ws services are keyed by `(host, path)` and owned
  by whichever client registered them, so different clients can serve different
  locations on the **same** host (first-come-first-served per path); a `tcp` host
  is owned wholesale.
- **Dynamic source-IP whitelist**: each service has an atomically swappable CIDR
  allow list, enforced at L4 and again at the HTTP layer, and changeable at
  runtime via `tbox whitelist` (keyed by service URL).

## Build

Requires Go ≥ 1.24.7. sing-box REALITY needs the `with_utls` tag (handled by the
Makefile):

```sh
make build        # -> bin/tbox
make test         # unit + integration (integration makes a real handshake to the mimic host)
```

Or install directly (the `with_utls` tag is required for REALITY):

```sh
go install -tags with_utls github.com/juliuswwj/tbox/cmd/tbox@latest
```

Prebuilt binaries for tagged releases are published on the
[releases page](https://github.com/juliuswwj/tbox/releases) by the release
workflow (linux/darwin/windows, amd64/arm64).

## Usage

On the **server** (VPS) — no keys or UUIDs to handle by hand:

```sh
# 1. Generate config + REALITY keys + first client, and print its token:
tbox init-server -c server.yaml --addr vps.example.com
# 2. Add more clients any time (prints each one's token):
tbox add-client  -c server.yaml laptop
# 3. Run it:
tbox server -c server.yaml
```

`init-server` writes a complete `server.yaml` (REALITY keypair, short id, one
client). `add-client` appends a client with a freshly generated UUID and prints
its token. Re-print existing tokens with `tbox gen-token -c server.yaml`.

On the **client** (local) — fill `client.yaml` (see
[`configs/client.example.yaml`](configs/client.example.yaml)) with the token and
your `publish:` URLs; supply certs there only if the server doesn't:

```sh
tbox client -c client.yaml

# forward proxy:
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# runtime whitelist control, keyed by service URL (talks to the client's admin API):
tbox whitelist -c client.yaml show
tbox whitelist -c client.yaml set    tcp://ssh.dc.example.com 203.0.113.0/24
tbox whitelist -c client.yaml add    tcp://ssh.dc.example.com 198.51.100.7/32
tbox whitelist -c client.yaml remove tcp://ssh.dc.example.com 203.0.113.0/24
```

## Running as a service

Hardened systemd units (run as an unprivileged `tbox` user; server binds `:443`
via `CAP_NET_BIND_SERVICE`) are in [`deploy/systemd/`](deploy/systemd/); see
[`deploy/README.md`](deploy/README.md) for install steps.

## Notes & limitations

- The published HTTPS sites are normal public HTTPS; the anti-censorship
  property applies to the client→server carrier link only.
- `flow: xtls-rprx-vision` is intentionally not enabled (plain REALITY); the L4
  router replays the original ClientHello bytes so REALITY's handshake/fallback
  is unaffected.
- All publish traffic for a client rides one yamux session (head-of-line
  blocking is possible under heavy concurrency); multiple carrier connections
  are a future optimization.
- sing-box's Go API changes across releases; the dependency is pinned (see
  `go.mod`). Configs are built as JSON and loaded through sing-box's documented
  schema for stability.
