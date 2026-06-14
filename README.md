# tbox

[![test](https://github.com/juliuswwj/tbox/actions/workflows/test.yml/badge.svg)](https://github.com/juliuswwj/tbox/actions/workflows/test.yml)

A VLESS-REALITY tunnel built on [sing-box](https://sing-box.sagernet.org/),
serving two purposes over one censorship-resistant link that looks like ordinary
HTTPS traffic to a real site (e.g. `www.microsoft.com`):

1. **Service publishing** — expose local services through the VPS as public
   HTTPS:
   - a raw **TCP** service as a **WebSocket** under an HTTPS domain;
   - an **HTTP** service as a full site or a sub-location, with nginx-style URL
     and header rewriting.
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

- The **server** owns `:443` with an L4 SNI router. By SNI:
  - the **mimic** host (and unknown/empty SNI, probes) → embedded sing-box
    VLESS-REALITY inbound, which serves authenticated proxy clients and falls
    back to the genuine mimic site for everyone else;
  - a **registered publish domain** → TLS-terminated on the VPS (with the
    client-supplied cert) and reverse-proxied / WS-bridged to the owning client.
- The **client** runs an embedded sing-box (SOCKS5H inbound + VLESS-REALITY
  outbound). Forward proxying is pure sing-box. For publishing it opens one
  carrier connection to the server through the tunnel and runs a
  [yamux](https://github.com/hashicorp/yamux) session over it, so the server can
  open reverse streams toward the client per public request.
- **Multi-client & shared domains**: the server lists several client credentials
  (one VLESS UUID each). A domain is a table of path-prefix **locations**, each
  owned by the client that registered it — so different clients can contribute
  different locations to the **same** domain (e.g. client A serves `/`, client B
  serves `/b/`). One client provides the TLS cert for the domain; others add
  cert-free locations. Locations are first-come-first-served at the path level.
- **Dynamic source-IP whitelist**: each published domain has an atomically
  swappable CIDR allow list, enforced at L4 and again at the HTTP layer, and
  changeable at runtime via `tbox whitelist`.

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

On the **server** (VPS):

```sh
tbox gen-keypair                       # prints reality keys, short_id, a sample uuid
# fill server.yaml (see configs/server.example.yaml), then:
tbox gen-token -c server.yaml --client client-1   # -> token for the client
tbox server -c server.yaml
```

On the **client** (local):

```sh
# fill client.yaml (see configs/client.example.yaml) with the token + your certs
tbox client -c client.yaml

# forward proxy:
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# runtime whitelist control (talks to the client's admin API):
tbox whitelist -c client.yaml show
tbox whitelist -c client.yaml set    app.example.com 203.0.113.0/24
tbox whitelist -c client.yaml add    app.example.com 198.51.100.7/32
tbox whitelist -c client.yaml remove app.example.com 203.0.113.0/24
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
