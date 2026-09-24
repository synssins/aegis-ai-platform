#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
ln -sf ../../scripts/sanitize-check.sh .git/hooks/pre-commit
chmod +x scripts/*.sh
echo "pre-commit sanitize hook installed"
