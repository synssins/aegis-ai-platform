#!/usr/bin/env bash
# CONSOLE ONLY. Resets the hub admin password and MFA. The one-time bootstrap password is printed
# BELOW, on this terminal (not in any file). First login then forces a new password and MFA enrolment.
set -euo pipefail; cd "$(dirname "$0")/.."
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
$DOCKER exec hub python3 /app/hub.py --reset-admin
echo "Sign in at https://<LAN_IP>/hub/login as 'admin' with the password above; you will be asked to enrol MFA and set your own password."
