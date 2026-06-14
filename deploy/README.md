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

## Let's Encrypt certificates (client)

Certs can be provided by the **server** (`server.yaml` `certs:`) — simplest, no
client-side cert plumbing — or by the **client**, which uploads them over the
tunnel. To use Let's Encrypt on the client, list the cert under `certs:` (names
are read from the SAN, so one cert covers all its `publish:` hosts):

```yaml
certs:
  - cert_path: "/etc/tbox/app.example.com.crt"   # fullchain
    key_path:  "/etc/tbox/app.example.com.key"   # privkey
publish:
  - url: "https://app.example.com/"
    upstream: "127.0.0.1:8080"
```

Two wrinkles with certbot's output:

1. **Permissions** — `/etc/letsencrypt/{live,archive}` are `0700 root`, so the
   unprivileged `tbox` user can't read `privkey.pem`.
2. **Renewal** — tbox reads the cert once at startup (and re-sends the same PEM
   on reconnect), so a renewed cert is only picked up after a restart.

The shipped deploy hook solves both: it copies each renewed cert/key into
`/etc/tbox` as `root:tbox 0640` and restarts the client.

```sh
sudo install -m 0755 deploy/letsencrypt-deploy-hook.sh \
     /etc/letsencrypt/renewal-hooks/deploy/tbox.sh

# initial issuance (also runs the hook so /etc/tbox/<domain>.{crt,key} appear):
sudo certbot certonly --standalone -d app.example.com \
     --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/tbox.sh
```

It writes `/etc/tbox/<domain>.crt` (fullchain) and `/etc/tbox/<domain>.key`
(privkey) — set the `certs:` entry in `client.yaml` to match. Renewals then
refresh those files and restart `tbox-client` automatically.

> Reading directly from `/etc/letsencrypt` instead of copying: the only barrier
> is the DAC perms (`/etc/letsencrypt/{live,archive}` are `0700 root`), **not**
> the systemd sandbox — `ProtectSystem=strict` keeps those paths readable, so no
> `ReadOnlyPaths=` drop-in is required. Fix the perms by either:
>
> - running `tbox-client` as root (drop `User=tbox`); or
> - granting the `tbox` user an ACL on **both** LE dirs — `live/` holds symlinks
>   into `archive/`, so both need `r-x`:
>   `sudo setfacl -Rm u:tbox:rX /etc/letsencrypt/live /etc/letsencrypt/archive`
>
> certbot can reset those perms on renewal, so the copy hook above is the
> sturdiest option.

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
