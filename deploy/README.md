# Deploying tbox with systemd

Unit files run tbox as an unprivileged `tbox` system user with sandboxing. The
server uses `CAP_NET_BIND_SERVICE` to bind `:443` without root.

## 1. Install the binary

Build with the required `with_utls` tag (see the top-level Makefile) and install:

```sh
make build
sudo install -m 0755 bin/tbox /usr/local/bin/tbox
```

## 2. Create the service user

```sh
sudo install -m 0644 deploy/systemd/tbox.sysusers.conf /usr/lib/sysusers.d/tbox.conf
sudo systemd-sysusers
# or, without sysusers:  sudo useradd --system --no-create-home --shell /usr/sbin/nologin tbox
```

## 3. Lay down config (root-owned, group-readable by tbox)

```sh
sudo mkdir -p /etc/tbox
# server:
sudo cp configs/server.example.yaml /etc/tbox/server.yaml
# client:
sudo cp configs/client.example.yaml /etc/tbox/client.yaml   # and the cert/key files it references

# server.yaml holds the REALITY private key; client.yaml/certs hold private keys.
sudo chown -R root:tbox /etc/tbox
sudo chmod 0750 /etc/tbox
sudo chmod 0640 /etc/tbox/*.yaml /etc/tbox/*.key /etc/tbox/*.crt 2>/dev/null || true
```

## 4. Install and start the unit

Server (VPS):

```sh
sudo install -m 0644 deploy/systemd/tbox-server.service /etc/systemd/system/tbox-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now tbox-server
sudo journalctl -u tbox-server -f
```

Client (local machine):

```sh
sudo install -m 0644 deploy/systemd/tbox-client.service /etc/systemd/system/tbox-client.service
sudo systemctl daemon-reload
sudo systemctl enable --now tbox-client
sudo journalctl -u tbox-client -f
```

## Notes

- The units pin config to `/etc/tbox/{server,client}.yaml`. To use another path,
  override with a drop-in: `sudo systemctl edit tbox-server` and set a new
  `ExecStart=`.
- `ProtectSystem=strict` makes the whole filesystem read-only **but still
  readable** — it doesn't hide anything. tbox only reads its config/certs and
  writes no state, so no `ReadWritePaths=` is needed (the `ReadOnlyPaths=/etc/tbox`
  in the unit is just documentation; under `ProtectSystem=strict` it is already
  read-only). Reading certs from any path (e.g. `/etc/letsencrypt`) works without
  a `ReadOnlyPaths=` drop-in; the only thing that can block it is the files' own
  permissions (DAC), not the sandbox.
- `tbox whitelist -c /etc/tbox/client.yaml ...` talks to the client's local
  admin port and can be run by hand while the service is active.

### Enabling the L2 tunnel (TAP)

The shipped units are hardened for the publishing/proxy roles and intentionally
**cannot** create a TAP device, write sysctls, or add iptables rules. When you
turn on the L2 tunnel (`tun.enable` with a native `tap`, NAT, or passthrough),
add a drop-in that relaxes exactly what the data plane needs. Server example
(`sudo systemctl edit tbox-server`):

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
PrivateDevices=no                 # allow /dev/net/tun
ProtectKernelTunables=no          # allow net.ipv4.ip_forward (enable_nat)
DeviceAllow=/dev/net/tun rw
```

A client that uses a native `tap` or `accept_default_route` needs the same
`CAP_NET_ADMIN` + `PrivateDevices=no` + `DeviceAllow=/dev/net/tun rw`. A client
that only exposes a `udp:` endpoint for `udpt.py` needs none of this — the udpt
process owns its own TAP. IPv6 passthrough additionally needs `ndppd` installed
and configured for the pool prefix; tbox calls `systemctl restart ndppd`, which
requires the unit to be able to run that (drop `NoNewPrivileges` or grant the
specific polkit/sudo rule per your policy).

## Let's Encrypt certificates

The cert's domain names are read from its SAN, so one cert (incl. a wildcard)
covers all of its `publish:` hosts; you never repeat the domain. Pick ONE of the
three setups below. Two facts to keep in mind for the client-side options:

- **Permissions** — `/etc/letsencrypt/{live,archive}` are `0700 root`, so the
  unprivileged `tbox` user can't read `privkey.pem` without help.
- **Renewal** — tbox reads certs at startup, so a renewed cert is picked up only
  after `tbox-client` restarts.

### Option A — server provides the cert (simplest)

certbot runs on the VPS; nothing cert-related on the client. The `tbox-server`
process runs as root or via the deploy hook below; point `server.yaml` at it:

```yaml
# /etc/tbox/server.yaml
certs:
  - cert_path: "/etc/tbox/dc.example.com.crt"
    key_path:  "/etc/tbox/dc.example.com.key"
```

```yaml
# /etc/tbox/client.yaml — no certs: section at all
publish:
  - url: "https://app.dc.example.com/"
    upstream: "127.0.0.1:8080"
```

### Option B — client cert via the copy hook (recommended for client-held certs)

The shipped hook copies each renewed cert/key into `/etc/tbox` as `root:tbox
0640` and restarts the client (solves both perms and renewal):

```sh
sudo install -m 0755 deploy/letsencrypt-deploy-hook.sh \
     /etc/letsencrypt/renewal-hooks/deploy/tbox.sh
sudo certbot certonly --standalone -d app.example.com \
     --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/tbox.sh
```

```yaml
# /etc/tbox/client.yaml — hook writes /etc/tbox/<domain>.{crt,key}
certs:
  - cert_path: "/etc/tbox/app.example.com.crt"
    key_path:  "/etc/tbox/app.example.com.key"
publish:
  - url: "https://app.example.com/"
    upstream: "127.0.0.1:8080"
```

### Option C — cert is copied in from elsewhere (no local certbot)

Use this when certbot runs somewhere else (e.g. the VPS or a cert manager) and
something `scp`/`rsync`s the renewed cert+key onto the client. There is no local
certbot, so no `renewal-hooks/` to fire — instead a **root cron** job watches the
files and, when they change, re-applies the `tbox` read ACL and restarts the
client. (No `ReadOnlyPaths=` drop-in is needed: `ProtectSystem=strict` keeps the
files readable; only the file perms matter, which the ACL fixes.)

```sh
# the watcher: setfacl + restart tbox-client whenever a watched file changes
sudo install -m 0755 deploy/cert-watch.sh /usr/local/sbin/tbox-cert-watch.sh

# run it every minute as root, listing your copied-in cert + key:
printf '* * * * * root /usr/local/sbin/tbox-cert-watch.sh %s %s\n' \
  /etc/tbox/app.example.com.crt /etc/tbox/app.example.com.key \
  | sudo tee /etc/cron.d/tbox-cert-watch
```

```yaml
# /etc/tbox/client.yaml — point at wherever the cert is copied to
certs:
  - cert_path: "/etc/tbox/app.example.com.crt"
    key_path:  "/etc/tbox/app.example.com.key"
publish:
  - url: "https://app.example.com/"
    upstream: "127.0.0.1:8080"
```

The watcher uses an ACL (`setfacl -m u:tbox:r`), so the copied files can stay
`root:root 0600` — re-copying doesn't lock tbox out, and the restart picks up the
new cert. (Prefer an event-driven trigger? A systemd `.path` unit watching the
files can call the same script instead of cron.)

> Running `tbox-client` as root (drop `User=tbox` from the unit) avoids the ACL
> entirely; you still need the cron restart so the renewed cert is loaded.

## Troubleshooting

- **`start sing-box: address family not supported by protocol`** — the unit's
  `RestrictAddressFamilies` is missing `AF_NETLINK`, which sing-box needs for its
  network/interface monitor. The shipped units include it; if you have an older
  copy, add `AF_NETLINK` (e.g. `sudo systemctl edit tbox-server`):

  ```ini
  [Service]
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
  ```

  then `sudo systemctl daemon-reload && sudo systemctl restart tbox-server`.
