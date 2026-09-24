#!/usr/bin/env bash
# First-install only: write the hub's basic-auth file from HUB_ADMIN_PASSWORD_HASH in .env.
# Afterwards the password is rotated from /hub (Access -> Admin password); never edit the file by hand.
set -euo pipefail; cd "$(dirname "$0")/.."
H=$(grep -E '^HUB_ADMIN_PASSWORD_HASH=' .env | cut -d= -f2- | sed -E "s/^'(.*)'$/\1/")
[ -n "$H" ] || { echo "HUB_ADMIN_PASSWORD_HASH missing in .env (docker run --rm caddy:2.11.4 caddy hash-password --plaintext '<pw>')"; exit 1; }
sudo install -d -m 700 caddy/sites-enabled
printf '# Hub administrator credential. Managed from /hub (Access -> Admin password). bcrypt.\nbasic_auth {\n    admin %s\n}\n' "$H" | sudo tee caddy/sites-enabled/hub-auth.conf >/dev/null
sudo chmod 600 caddy/sites-enabled/hub-auth.conf; echo "hub-auth.conf seeded"
