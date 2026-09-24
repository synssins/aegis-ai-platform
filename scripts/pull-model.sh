#!/usr/bin/env bash
# Pull an Ollama model into /data/ai-unified/llm/gguf WITHOUT giving the production
# ollama container internet access. Runs a throw-away ollama on the default (egress) bridge,
# pulls, exits. The production container sees the new model immediately (shared volume).
set -euo pipefail
MODEL="${1:?usage: pull-model.sh <model[:tag]>}"
docker run --rm \
  -v /data/ai-unified/llm/gguf:/root/.ollama \
  --entrypoint /bin/sh \
  ollama/ollama:0.34.3 \
  -c "ollama serve >/dev/null 2>&1 & for i in \$(seq 1 30); do ollama list >/dev/null 2>&1 && break; sleep 1; done; ollama pull '$MODEL'"
