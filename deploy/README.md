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
- `ReadOnlyPaths=/etc/tbox` and `ProtectSystem=strict` mean the process cannot
  write anywhere except `/tmp` (private). tbox writes no state files.
- If you run the client's published cert/keys outside `/etc/tbox`, add that path
  to the unit (e.g. a `ReadOnlyPaths=` drop-in) since `ProtectSystem=strict`
  hides most of the filesystem.
- `tbox whitelist -c /etc/tbox/client.yaml ...` talks to the client's local
  admin port and can be run by hand while the service is active.

## Let's Encrypt certificates (client)

The published domain's cert/key live on the **client** (it uploads them to the
server over the tunnel). Point `client.yaml` at them:

```yaml
publish:
  - domain: "app.example.com"
    cert_path: "/etc/tbox/app.example.com.crt"
    key_path:  "/etc/tbox/app.example.com.key"
    mode: "http"
    routes:
      - { path: "/", upstream: "127.0.0.1:8080" }
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
(privkey) — set `cert_path`/`key_path` in `client.yaml` to match. Renewals then
refresh those files and restart `tbox-client` automatically.

> Alternatives: run `tbox-client` as root (drop `User=tbox` and add a
> `ReadWritePaths=`/`ReadOnlyPaths=/etc/letsencrypt` drop-in), or grant the
> `tbox` user an ACL on the LE dirs (`setfacl -Rm u:tbox:rX /etc/letsencrypt/{live,archive}`)
> — but certbot can reset those perms on renewal, so the copy hook is the
> sturdiest. Either way, if your certs stay outside `/etc/tbox`, add a
> `ReadOnlyPaths=` drop-in for that path because `ProtectSystem=strict` is set.

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
