#!/usr/bin/env bash
# CONSOLE ONLY — recovery. Lifts "require a device certificate for administrators" when the device that held
# the certificate is gone. Audited. Afterwards: sign in (password + TOTP), issue a new certificate under
# Access -> Devices, revoke the lost one, re-enable the requirement.
set -euo pipefail; cd "$(dirname "$0")/.."
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
$DOCKER exec hub python3 /app/hub.py --device-recovery
