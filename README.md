# tbox

[![test](https://github.com/juliuswwj/tbox/actions/workflows/test.yml/badge.svg)](https://github.com/juliuswwj/tbox/actions/workflows/test.yml)

A VLESS-REALITY tunnel built on [sing-box](https://sing-box.sagernet.org/),
serving three purposes over one censorship-resistant link that looks like
ordinary HTTPS traffic to a real site (e.g. `www.microsoft.com`):

1. **Service publishing** — expose local services through the VPS, identified by
   a URL whose scheme picks the mode:
   - `https://host/path` — an **HTTP** service as a full site or sub-location,
     with nginx-style URL/header rewriting;
   - `wss://host/path` — a raw **TCP** service as a **WebSocket**;
   - `tcp://host` — a raw **TCP** service as **TLS+TCP** (TLS terminated by SNI,
     then piped raw — e.g. ssh);
   - `socks5://host` — a restricted **SOCKS5** proxy where the client is the
     SOCKS5 server and only dials destinations on an `allow_dest` list (so it is
     never an open proxy).

   These coexist under one certificate, e.g. all of `https://dc.example.com/`,
   `https://app.dc.example.com/location/`, `wss://app.dc.example.com/tunnel/ssh`,
   and `tcp://ssh.dc.example.com` served by a cert for `[dc.example.com,
   *.dc.example.com]`.
2. **SOCKS5H proxy** — a local SOCKS5H port whose traffic egresses from the VPS,
   to get through a monitored gateway.
3. **L2 tunnel (TAP)** — an Ethernet-level virtual network over the same
   carrier. The server is a learning bridge (a native Go re-implementation of
   the `udpt.py` UDP bridge); clients join as nodes either through their own TAP
   device or by letting **unmodified `udpt.py` clients** connect to a local UDP
   socket. Supports a virtual subnet, global egress (v4 NAT), and IPv6
   transparent passthrough (`ndppd`). See [L2 tunnel](#l2-tunnel-tap).

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
  - a **tcp / socks5 service** → TLS terminated on the VPS, then raw-piped to the
    owning client (which dials the upstream, or runs a SOCKS5 server enforcing
    `allow_dest`);
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
- **Brute-force banning** (optional): the HTTP path can watch upstream responses
  and ban abusive sources fail2ban-style — by default a `POST` answered with
  `401`/`403` counts as a failed auth, and an IP that crosses the threshold is
  blocked for an hour, escalating to its whole `/24`. See
  [HTTP brute-force banning](#http-brute-force-banning).
- **L2 tunnel** (when enabled): a dedicated yamux stream per client carries
  length-prefixed Ethernet frames. The server runs a userspace learning switch
  whose ports are the local TAP plus each client's stream; clients run the same
  switch with the carrier stream as the uplink and local TAP and/or a UDP
  endpoint as ports. Forwarding is by MAC, so two local `udpt.py` clients on one
  tbox client are switched on that host and never traverse the carrier.

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

## L2 tunnel (TAP)

The L2 tunnel turns the carrier into an Ethernet segment shared by the server
and all clients. It absorbs the model of the reference `udpt.py` bridge but runs
the switching natively in Go and rides the existing encrypted carrier (no extra
UDP port is exposed to the internet, so the "looks like HTTPS" property holds).

```
 udpt.py ─udp─▶┐                                            ┌── server TAP (tbox0, gateway)
 udpt.py ─udp─▶┤ tbox client (switch) ══tun stream══▶ tbox server (switch hub) ─┼── NAT egress (eth0)
 native TAP ───┘    (uplink + UDP + TAP ports)              :443                └── IPv6 passthrough (ndppd)
```

- **Server** (the hub) creates a TAP device and switches between the local TAP
  and each client's carrier stream by MAC. Enable it in `server.yaml`:

  ```yaml
  tun:
    enable: true
    pool_v4: "10.42.0.0/24"   # gateway defaults to 10.42.0.1
    enable_nat: true          # MASQUERADE the pool out wan_interface for global egress
    wan_interface: "eth0"
    enable_passthrough: true  # add /80 routes + restart ndppd for global IPv6
  ```

- **Client** (a leaf) enables at least one local endpoint in `client.yaml`:

  ```yaml
  tun:
    enable: true
    accept_default_route: false   # set true (with tap) to route everything via the tunnel
    tap:                          # make this host a node (IPv4 auto-assigned if omitted)
      name: "tbox0"
    udp:                          # let unmodified udpt.py clients join over UDP
      listen: "127.0.0.1:3390"
  ```

- **Connecting `udpt.py`** (unchanged) to a client's UDP endpoint:

  ```sh
  python3 udpt.py --target 127.0.0.1:3390 --tap tap0 --ip 10.42.0.20/24
  ```

  Each udpt peer is a distinct switch port, so multiple udpt clients on one tbox
  client reach each other locally and reach the server-side segment over the
  tunnel. Virtual IPs are either server-assigned (native TAP) or self-configured
  (`udpt.py --ip`).

The server, and any client using a native TAP or `accept_default_route`, needs
`CAP_NET_ADMIN`. IPv6 passthrough additionally requires `ndppd` installed and
configured by the operator for the pool prefix; tbox adds the per-host `/80`
routes and restarts it.

## HTTP brute-force banning

Because the publish path is a reverse proxy, tbox sees both the **real client
IP** (the connection remote, never `X-Forwarded-For`) and the **upstream
response status**. That's enough for fail2ban-style protection of an app's login
without any change to the app. Enable it in `server.yaml`:

```yaml
ban:
  enable: true
  # What counts as one failed auth attempt (defaults shown):
  methods: ["POST"]        # only these request methods
  statuses: [401, 403]     # ... answered with these statuses
  # path: "/websh/api/login"  # optional: restrict to a login path prefix
  # Thresholds:
  threshold: 5             # failures from one IP within `window` ...
  window: "10m"            # ... the sliding window ...
  ban_duration: "1h"       # ... ban that IP for this long.
  subnet_threshold: 2      # once this many distinct IPs in a /24 are banned,
                           # ban the whole /24 too (0 disables; IPv4 only).
  exempt: ["203.0.113.0/24"]  # sources never counted or banned (e.g. your own)
```

Why `POST` + `401/403` by default: a brute-forcer hammers `POST /api/login`,
while a normal first visit that hits an unauthenticated `GET /api/me` → `401` is
a `GET` and is **not** counted, so legitimate users aren't banned. A banned
source gets a `403` on every HTTP publish service (before any upstream work).
State is in-memory (cleared on restart). This guards the HTTP publish path only;
raw `tcp`/`socks5` services are not covered.

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
- The L2 tunnel carries Ethernet frames over the TCP-based carrier, so tunneled
  TCP is subject to TCP-over-TCP degradation under loss; it suits LAN-style
  interconnect and moderate throughput. MTU defaults to 1448. Global-egress
  default-route uses `server_addr` for the carrier host-route exception, which
  applies when `server_addr` is an IP (best-effort, logged, for a hostname).
- sing-box's Go API changes across releases; the dependency is pinned (see
  `go.mod`). Configs are built as JSON and loaded through sing-box's documented
  schema for stability.
