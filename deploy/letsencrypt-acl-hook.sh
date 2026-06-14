#!/bin/sh
# certbot deploy hook for tbox "Option C" (client reads /etc/letsencrypt directly).
#
# Runs as root after every successful renewal — i.e. exactly when the cert files
# change. certbot writes NEW files into /etc/letsencrypt/archive/<domain>/ on
# renewal, and those do not inherit a previously-applied ACL, so the tbox user
# would lose read access. This hook re-applies the ACL (idempotent) and restarts
# the client so it re-reads the renewed cert.
#
# Install:
#   sudo install -m 0755 deploy/letsencrypt-acl-hook.sh \
#        /etc/letsencrypt/renewal-hooks/deploy/tbox-acl.sh
# Apply once now (for an already-issued cert):
#   sudo /etc/letsencrypt/renewal-hooks/deploy/tbox-acl.sh
set -eu

USER_NAME=tbox
SERVICE=tbox-client

setfacl -Rm "u:${USER_NAME}:rX" /etc/letsencrypt/live /etc/letsencrypt/archive

if systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1; then
    systemctl try-restart "$SERVICE"
fi
