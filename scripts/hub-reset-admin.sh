#!/usr/bin/env bash
# CONSOLE ONLY — recovery. Removes every hub account; the first-run setup wizard then appears at /hub,
# where you create the administrator and enrol MFA in the browser. No passwords are printed or stored.
set -euo pipefail; cd "$(dirname "$0")/.."
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
$DOCKER exec hub python3 /app/hub.py --reset-admin
