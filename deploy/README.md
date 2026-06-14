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
