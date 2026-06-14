#!/bin/sh
# tbox cert watcher — for clients where the TLS cert/key are COPIED in from
# elsewhere (no local certbot, so no renewal-hooks to fire). Run from root cron;
# when any watched file changes it grants the tbox user read access (via ACL,
# so the copied file's owner/mode don't matter) and restarts tbox-client.
#
# Install:
#   sudo install -m 0755 deploy/cert-watch.sh /usr/local/sbin/tbox-cert-watch.sh
#   # /etc/cron.d/tbox-cert-watch  (runs every minute as root):
#   * * * * * root /usr/local/sbin/tbox-cert-watch.sh \
#       /etc/tbox/app.example.com.crt /etc/tbox/app.example.com.key
set -eu

SERVICE=tbox-client
STAMP=/run/tbox-cert-watch.sha256

[ "$#" -gt 0 ] || { echo "usage: $0 <cert-or-key-file>..." >&2; exit 2; }
for f in "$@"; do
	[ -r "$f" ] || { echo "tbox-cert-watch: $f not found yet" >&2; exit 0; }
done

cur=$(sha256sum "$@" | sha256sum | cut -d' ' -f1)
if [ -f "$STAMP" ] && [ "$cur" = "$(cat "$STAMP")" ]; then
	exit 0 # unchanged
fi

# Grant the service user read access without changing ownership/mode.
setfacl -m u:tbox:r "$@"
systemctl try-restart "$SERVICE"
echo "$cur" >"$STAMP"
