#!/bin/sh
# certbot deploy hook for tbox.
#
# Let's Encrypt stores keys under /etc/letsencrypt/{live,archive}/ as root-only
# (0700), so the unprivileged `tbox` service user cannot read them. This hook
# copies each renewed cert/key into /etc/tbox as root:tbox 0640 (readable by the
# service) and restarts tbox-client so it re-reads and re-registers the cert.
#
# Install:
#   sudo install -m 0755 deploy/letsencrypt-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/tbox.sh
# It then runs automatically on every renewal. To also run it for the initial
# issuance, pass it explicitly:
#   sudo certbot certonly --standalone -d app.example.com \
#        --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/tbox.sh
#
# certbot sets $RENEWED_LINEAGE (the live/<name> dir) for each renewed cert.
set -eu

DEST=/etc/tbox
SERVICE=tbox-client

install -d -m 0750 -o root -g tbox "$DEST"

name=$(basename "$RENEWED_LINEAGE")
install -m 0640 -o root -g tbox "$RENEWED_LINEAGE/fullchain.pem" "$DEST/$name.crt"
install -m 0640 -o root -g tbox "$RENEWED_LINEAGE/privkey.pem"  "$DEST/$name.key"

# Restart only if the unit exists/active (avoids errors on first issuance).
if systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1; then
    systemctl try-restart "$SERVICE"
fi
