#!/usr/bin/env bash
# Pull an Ollama model into the shared model store WITHOUT giving the production ollama container
# internet access: a throw-away ollama on the default (egress) bridge pulls, then exits. The
# production container sees the new model immediately (shared volume). The hub's Models page does
# the same thing through the `modeld` sidecar; this script is the console equivalent.
set -euo pipefail
MODEL="${1:?usage: pull-model.sh <model[:tag]>}"
cd "$(dirname "$0")/.."
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
$DOCKER run --rm \
  -v "$PWD/llm/gguf:/root/.ollama" \
  --entrypoint /bin/sh \
  ollama/ollama:0.34.3 \
  -c "ollama serve >/dev/null 2>&1 & for i in \$(seq 1 30); do ollama list >/dev/null 2>&1 && break; sleep 1; done; ollama pull '$MODEL'"
