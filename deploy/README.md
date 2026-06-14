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

### Option C — client reads /etc/letsencrypt directly (no copy)

Point `client.yaml` straight at certbot's files. Grant the `tbox` user an ACL on
**both** LE dirs (`live/` symlinks into `archive/`, so both need `r-x`), and add
a restart hook (the systemd sandbox does NOT block this — `ProtectSystem=strict`
keeps the paths readable; the only barrier is the `0700` perms, which the ACL
fixes — no `ReadOnlyPaths=` drop-in is needed):

```sh
sudo setfacl -Rm u:tbox:rX /etc/letsencrypt/live /etc/letsencrypt/archive

printf '#!/bin/sh\nsystemctl restart tbox-client\n' \
  | sudo tee /etc/letsencrypt/renewal-hooks/deploy/tbox-restart.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/tbox-restart.sh
```

```yaml
# /etc/tbox/client.yaml — read certbot's files in place
certs:
  - cert_path: "/etc/letsencrypt/live/app.example.com/fullchain.pem"
    key_path:  "/etc/letsencrypt/live/app.example.com/privkey.pem"
publish:
  - url: "https://app.example.com/"
    upstream: "127.0.0.1:8080"
```

> certbot can reset perms on renewal (re-running the ACL), so Option B is a bit
> sturdier than C. Running `tbox-client` as root (drop `User=tbox` from the unit)
> also works and needs no ACL.

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
